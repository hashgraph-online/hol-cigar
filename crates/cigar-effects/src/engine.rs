//! Repository-backed effect state machine and fenced dispatcher.

use crate::{
    ConnectorDescriptor, DispatchContext, DispatchObservation, DispatchPermit, DurableEffectRecord,
    EffectAuthorization, EffectConnector, EffectError, EffectErrorCode, EffectOutboxEntry,
    EffectOutboxState, EffectRecordAuthenticator, EffectRecordSeal, KernelDispatchContextSeal,
    ReconcileObservation,
};
use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_protocol::{
    ApprovalKind, Capability, CompensationLink, CompensationSpec, ContentDigest, EffectApproval,
    EffectAttempt, EffectIntent, EffectJournalEvent, EffectReceipt, EffectState, ReceiptOutcome,
    ReconciliationOutcome, ReconciliationReport, RecordId, RetryPolicy, RiskLevel, SchemaVersion,
    UtcTimestamp, Validate,
};
use cigar_store::{
    AccessContext, CancellationToken, EffectRecordEnvelope, IdempotencyIdentity, OutboxMessage,
    ReadTransaction, Repository, SnapshotSelection, StoreError, StoreErrorCode, StoreRevision,
    WriteTransaction,
};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const MAX_PERSIST_RETRIES: usize = 16;
const MAX_LATEST_READ_RETRIES: usize = 16;
const MAX_EFFECT_ATTEMPTS: usize = 1_024;
const MAX_EFFECT_RECONCILIATIONS: usize = 4_096;
const AUTHENTICATED_RECORD_SCHEMA: &str = "cigar.authenticated-effect-record.v1";
type EffectCheckpointIdentity = (RecordId, RecordId);
type EffectCheckpoint = (ContentDigest, u64, ContentDigest);
type EffectCheckpointMap = BTreeMap<EffectCheckpointIdentity, EffectCheckpoint>;

/// Process-local keyed authenticator used by the compatibility constructor.
///
/// Its random key and rollback checkpoints never enter the effect repository. Deployments that
/// require restart or cross-process availability should use [`EffectEngine::new_with_authenticator`]
/// with a tenant KMS/checkpoint implementation; loss of this process key fails closed.
pub struct ProcessEffectAuthenticator {
    key_id: String,
    key: Option<[u8; 32]>,
    checkpoints: Mutex<EffectCheckpointMap>,
}

impl ProcessEffectAuthenticator {
    /// Creates a deterministic key epoch for embeddings that securely provision and retain it.
    pub fn from_key(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self, EffectError> {
        let key_id = key_id.into();
        EffectRecordSeal::new(key_id.clone(), raw_multihash(&key)?)?;
        Ok(Self {
            key_id,
            key: Some(key),
            checkpoints: Mutex::new(BTreeMap::new()),
        })
    }

    fn process_local() -> Self {
        Self {
            key_id: "process-ephemeral-v1".to_owned(),
            key: process_random_key(),
            checkpoints: Mutex::new(BTreeMap::new()),
        }
    }
}

impl std::fmt::Debug for ProcessEffectAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessEffectAuthenticator")
            .field("key_id", &self.key_id)
            .field("key_available", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl EffectRecordAuthenticator for ProcessEffectAuthenticator {
    fn seal(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
    ) -> Result<EffectRecordSeal, EffectError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| EffectError::new(EffectErrorCode::Unavailable))?;
        EffectRecordSeal::new(
            self.key_id.clone(),
            keyed_record_authenticator(key, tenant_id, canonical_record)?,
        )
    }

    fn verify(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
        seal: &EffectRecordSeal,
    ) -> Result<(), EffectError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| EffectError::new(EffectErrorCode::Unavailable))?;
        if seal.key_id() != self.key_id
            || seal.signed_proof().is_some()
            || !constant_time_equal(
                keyed_record_authenticator(key, tenant_id, canonical_record)?
                    .as_str()
                    .as_bytes(),
                seal.authenticator().as_str().as_bytes(),
            )
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
        Ok(())
    }

    fn observe_latest(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError> {
        let mut checkpoints = self
            .checkpoints
            .lock()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let identity = (tenant_id.clone(), effect_id.clone());
        match checkpoints.get(&identity) {
            Some((current_intent, version, current))
                if intent_digest != current_intent
                    || effect_version < *version
                    || (effect_version == *version && authenticator != current) =>
            {
                Err(EffectError::new(EffectErrorCode::CorruptJournal))
            }
            Some((_current_intent, version, _current)) if effect_version == *version => Ok(()),
            Some(_) | None => {
                checkpoints.insert(
                    identity,
                    (intent_digest.clone(), effect_version, authenticator.clone()),
                );
                Ok(())
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedEffectRecord {
    schema_version: String,
    record: DurableEffectRecord,
    seal: EffectRecordSeal,
}

/// Content-free fields that must exactly match the external monotonic checkpoint for one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCheckpointObservation {
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// Immutable digest of the first durable intent.
    pub intent_digest: ContentDigest,
    /// Latest durable effect projection version.
    pub effect_version: u64,
    /// Digest of the exact tenant signature authenticating this projection.
    pub authenticator: ContentDigest,
}

/// Decodes and validates one protected envelope for backup/checkpoint completeness comparison.
///
/// This validates the envelope digest, closed record shape, semantic journal, and seal shape. The
/// caller must separately verify the tenant signature or compare its authenticator against a
/// trusted external checkpoint; protected record bytes are never returned.
pub fn persisted_effect_checkpoint_observation(
    envelope: &EffectRecordEnvelope,
) -> Result<EffectCheckpointObservation, EffectError> {
    let authenticated = decode_authenticated_effect_record(envelope)?;
    verify_record(&authenticated.record)?;
    Ok(EffectCheckpointObservation {
        effect_id: authenticated.record.intent.effect_id,
        intent_digest: authenticated.record.intent_digest,
        effect_version: authenticated.record.effect_version,
        authenticator: authenticated.seal.authenticator().clone(),
    })
}

/// Read-only verification of one latest persisted effect envelope, including its semantic journal,
/// tenant-key seal, and production external rollback checkpoint when the authenticator supports it.
pub fn verify_persisted_effect_record(
    tenant_id: &RecordId,
    envelope: &EffectRecordEnvelope,
    authenticator: &dyn EffectRecordAuthenticator,
) -> Result<(), EffectError> {
    let authenticated = decode_authenticated_effect_record(envelope)?;
    let canonical_record = serde_json::to_vec(&authenticated.record)
        .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
    authenticator.verify_latest_read_only(
        tenant_id,
        &authenticated.record.intent.effect_id,
        &authenticated.record.intent_digest,
        authenticated.record.effect_version,
        &canonical_record,
        &authenticated.seal,
    )?;
    verify_record(&authenticated.record)
}

/// Thread-safe repository-backed effect kernel.
pub struct EffectEngine<R: Repository> {
    repository: Arc<R>,
    access: AccessContext,
    authenticator: Arc<dyn EffectRecordAuthenticator>,
    connectors: RwLock<BTreeMap<String, RegisteredConnector>>,
}

#[derive(Clone)]
struct RegisteredConnector {
    descriptor: ConnectorDescriptor,
    implementation: Arc<dyn EffectConnector>,
}

impl<R: Repository> std::fmt::Debug for EffectEngine<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let connector_count = self.connectors.read().map_or(0, |items| items.len());
        formatter
            .debug_struct("EffectEngine")
            .field("access", &self.access)
            .field("connector_count", &connector_count)
            .finish()
    }
}

impl<R: Repository> EffectEngine<R> {
    /// Creates an engine in one exact tenant/purpose capability.
    #[must_use]
    pub fn new(repository: Arc<R>, access: AccessContext) -> Self {
        Self::new_with_authenticator(repository, access, default_process_authenticator())
    }

    /// Creates an engine with an explicit tenant-key and external-checkpoint boundary.
    #[must_use]
    pub fn new_with_authenticator(
        repository: Arc<R>,
        access: AccessContext,
        authenticator: Arc<dyn EffectRecordAuthenticator>,
    ) -> Self {
        Self {
            repository,
            access,
            authenticator,
            connectors: RwLock::new(BTreeMap::new()),
        }
    }

    /// Registers one validated immutable connector descriptor.
    pub fn register_connector(
        &self,
        connector: Arc<dyn EffectConnector>,
    ) -> Result<(), EffectError> {
        let descriptor = catch_unwind(AssertUnwindSafe(|| connector.descriptor()))
            .map_err(|_panic| EffectError::new(EffectErrorCode::Unavailable))?;
        descriptor.validate()?;
        let mut connectors = self
            .connectors
            .write()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if connectors.contains_key(&descriptor.connector) {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        connectors.insert(
            descriptor.connector.clone(),
            RegisteredConnector {
                descriptor,
                implementation: connector,
            },
        );
        Ok(())
    }

    /// Persists a normalized intent and `Prepared` projection before any external action.
    pub fn prepare(
        &self,
        intent: EffectIntent,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        intent
            .validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        if !authorization.permits_proposal()
            || authorization.now < intent.created_at
            || authorization.now >= intent.expires_at
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let descriptor = self.connector_descriptor(&intent.connector)?;
        let operation = descriptor
            .operation(&intent.operation)
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        let retry_supported = match intent.retry_policy {
            RetryPolicy::Never => true,
            RetryPolicy::SameKeyIdempotent { .. } => operation.same_key_idempotent,
            RetryPolicy::ReconcileBeforeRetry => operation.supports_reconciliation,
        };
        let compensation_supported = match &intent.compensation {
            Some(compensation) => {
                operation.supports_compensation
                    && descriptor.operation(&compensation.operation).is_some()
            }
            None => true,
        };
        if !retry_supported || !compensation_supported {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let intent_digest = effect_intent_digest(&intent)?;
        if let Some(existing) = self.try_get(&intent.effect_id)? {
            return if existing.intent_digest == intent_digest && existing.intent == intent {
                Ok(existing)
            } else {
                Err(EffectError::new(EffectErrorCode::IdempotencyCollision))
            };
        }
        let record = DurableEffectRecord {
            intent: intent.clone(),
            intent_digest: intent_digest.clone(),
            state: EffectState::Prepared,
            effect_version: 0,
            approval: None,
            approval_digest: None,
            attempts: Vec::new(),
            receipts: Vec::new(),
            reconciliations: Vec::new(),
            compensation_link: None,
            journal: Vec::new(),
            outbox: None,
        };
        verify_record(&record)?;
        let identity = IdempotencyIdentity::new(
            format!("effect:{}:{}", intent.connector, intent.idempotency_scope),
            intent.idempotency_key.clone(),
            intent_digest,
        )
        .map_err(map_store_error)?;
        for _attempt in 0..MAX_PERSIST_RETRIES {
            let revision = self.latest_revision()?;
            let mut transaction = self
                .repository
                .begin_write(self.access.clone(), revision, CancellationToken::default())
                .map_err(map_store_error)?;
            let envelope = self.encode_record(&record)?;
            transaction
                .put_effect_record(envelope.clone())
                .map_err(map_store_error)?;
            match transaction.commit(Some(identity.clone())) {
                Ok(receipt) if !receipt.replayed => {
                    self.observe_envelope(&envelope)?;
                    return Ok(record);
                }
                Ok(_replayed) => {
                    return self
                        .try_get(&intent.effect_id)?
                        .ok_or_else(|| EffectError::new(EffectErrorCode::IdempotencyCollision));
                }
                Err(error) if error.code() == StoreErrorCode::RevisionConflict => continue,
                Err(error) if error.code() == StoreErrorCode::InvalidRecord => {
                    return Err(EffectError::new(EffectErrorCode::IdempotencyCollision));
                }
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(EffectError::new(EffectErrorCode::RevisionConflict))
    }

    /// Returns and integrity-verifies the complete current record.
    pub fn get(&self, effect_id: &RecordId) -> Result<DurableEffectRecord, EffectError> {
        self.try_get(effect_id)?
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    /// Returns and integrity-verifies a record at one exact durable repository revision.
    pub fn get_at_revision(
        &self,
        effect_id: &RecordId,
        revision: StoreRevision,
    ) -> Result<DurableEffectRecord, EffectError> {
        self.try_get_at(effect_id, SnapshotSelection::Revision(revision))?
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    /// Moves a prepared effect into explicit approval waiting.
    pub fn request_approval(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.permits_proposal()
            || authorization.now < record.intent.created_at
            || authorization.now >= record.intent.expires_at
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let payload = payload_digest(b"approval-requested", &record.intent_digest)?;
        let next = transition(
            record.clone(),
            EffectState::PendingApproval,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Authorizes dispatch after exact approval, policy, capability, bundle, target, and time checks.
    pub fn authorize(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        approval: Option<EffectApproval>,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.permits_dispatch(&record.intent)
            || authorization.now < record.intent.created_at
            || authorization.now >= record.intent.expires_at
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        match &approval {
            Some(approval) => verify_approval(&record, approval, authorization.now)?,
            None if record.intent.risk == RiskLevel::Low => {}
            None => return Err(EffectError::new(EffectErrorCode::Unauthorized)),
        }
        let exact_approval_digest = approval.as_ref().map(effect_approval_digest).transpose()?;
        let payload = payload_digest(
            b"authorization",
            &(record.intent_digest.clone(), exact_approval_digest.as_ref()),
        )?;
        let mut next = record.clone();
        next.approval = approval;
        next.approval_digest = exact_approval_digest;
        next = transition(
            next,
            EffectState::Authorized,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Rejects an approval request without any connector call.
    pub fn reject(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        evidence: ContentDigest,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.policy_allows
            || !authorization
                .capabilities
                .contains(&Capability::ApproveEffect)
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let next = transition(
            record.clone(),
            EffectState::Rejected,
            authorization.actor_id.clone(),
            event_id,
            evidence,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Expires a never-sent intent or authorization at its exclusive time boundary.
    pub fn expire(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        actor_id: RecordId,
        now: UtcTimestamp,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        let approval_expired = record
            .approval
            .as_ref()
            .is_some_and(|approval| now >= approval.expires_at);
        if now < record.intent.expires_at && !approval_expired {
            return Err(EffectError::new(EffectErrorCode::Expired));
        }
        let payload = payload_digest(b"expiry", &(record.intent_digest.clone(), now))?;
        let next = transition(
            record.clone(),
            EffectState::Expired,
            actor_id,
            event_id,
            payload,
            now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Cancels only a state for which no possible remote send is in flight.
    pub fn cancel(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.permits_proposal() || authorization.now < record.intent.created_at {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let payload = payload_digest(b"cancellation", &record.intent_digest)?;
        let next = transition(
            record.clone(),
            EffectState::Cancelled,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Atomically commits a dispatching attempt, fence, journal event, and outbox wakeup.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_dispatch(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        attempt_id: RecordId,
        outbox_message_id: RecordId,
        event_id: RecordId,
        deadline: UtcTimestamp,
        authorization: &EffectAuthorization,
    ) -> Result<DispatchPermit, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.permits_dispatch(&record.intent)
            || authorization.now < record.intent.created_at
            || authorization.now >= record.intent.expires_at
            || deadline <= authorization.now
            || deadline > record.intent.expires_at
            || record
                .approval
                .as_ref()
                .is_some_and(|approval| authorization.now >= approval.expires_at)
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let descriptor = self.connector_descriptor(&record.intent.connector)?;
        let operation = descriptor
            .operation(&record.intent.operation)
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        let dispatch_window = deadline
            .unix_nanos()
            .checked_sub(authorization.now.unix_nanos())
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        if dispatch_window > i128::from(descriptor.maximum_dispatch_nanos) {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        validate_retry_claim(&record, operation.same_key_idempotent)?;
        if record.attempts.len() >= MAX_EFFECT_ATTEMPTS {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        let attempt_number = u16::try_from(record.attempts.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
        let fencing_token = record
            .attempts
            .last()
            .map_or(Some(1), |attempt| attempt.fencing_token.checked_add(1))
            .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
        let attempt = EffectAttempt {
            schema_version: SchemaVersion::new("cigar.effect-attempt", 1)
                .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?,
            attempt_id: attempt_id.clone(),
            effect_id: effect_id.clone(),
            attempt_number,
            fencing_token,
            request_digest: record.intent_digest.clone(),
            started_at: authorization.now,
            deadline,
        };
        attempt
            .validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let outbox = EffectOutboxEntry {
            message_id: outbox_message_id.clone(),
            attempt_id: attempt_id.clone(),
            fencing_token,
            state: EffectOutboxState::Claimed,
        };
        let payload = payload_digest(b"dispatch-claim", &(&attempt, &outbox))?;
        let mut next = record.clone();
        next.attempts.push(attempt.clone());
        next.outbox = Some(outbox);
        next = transition(
            next,
            EffectState::Dispatching,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        let wake = OutboxMessage {
            message_id: outbox_message_id,
            topic: "effect.dispatch.v1".to_owned(),
            payload_digest: attempt.request_digest.clone(),
        };
        let persisted = self.persist_next(&record, &next, Some(wake))?;
        let seal = permit_seal(
            effect_id,
            &attempt_id,
            fencing_token,
            persisted.effect_version,
            &attempt.request_digest,
        )?;
        Ok(DispatchPermit {
            effect_id: effect_id.clone(),
            attempt_id,
            fencing_token,
            effect_version: persisted.effect_version,
            request_digest: attempt.request_digest,
            seal,
        })
    }

    /// Reconstructs a sealed permit solely from one exact durable in-flight record.
    ///
    /// This is the worker/recovery counterpart to [`Self::claim_dispatch`]. It never creates a
    /// new attempt and cannot authorize a record whose durable state, fence, or version changed.
    pub fn resume_dispatch(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
    ) -> Result<DispatchPermit, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        let attempt = record
            .attempts
            .last()
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let permit = DispatchPermit {
            effect_id: effect_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            fencing_token: attempt.fencing_token,
            effect_version: record.effect_version,
            request_digest: record.intent_digest.clone(),
            seal: permit_seal(
                effect_id,
                &attempt.attempt_id,
                attempt.fencing_token,
                record.effect_version,
                &record.intent_digest,
            )?,
        };
        verify_permit(&record, &permit)?;
        Ok(permit)
    }

    /// Performs one connector call only after rechecking the durable permit and current authority.
    pub fn dispatch(
        &self,
        permit: DispatchPermit,
        receipt_id: RecordId,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(&permit.effect_id)?;
        verify_permit(&record, &permit)?;
        let attempt = record
            .attempts
            .last()
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let connector = self.connector(&record.intent.connector)?;
        self.verify_connector_descriptor(&record.intent.connector, &connector)?;
        if !authorization.permits_dispatch(&record.intent)
            || authorization.now < record.intent.created_at
            || authorization.now >= record.intent.expires_at
            || authorization.now >= attempt.deadline
            || record
                .approval
                .as_ref()
                .is_some_and(|approval| authorization.now >= approval.expires_at)
        {
            return self.finalize_without_send(
                record,
                attempt,
                receipt_id,
                event_id,
                authorization,
                b"pre-send-authorization-denied",
            );
        }
        let connector_failure = stable_marker(b"connector-panic-or-error")?;
        let preconditions = match catch_unwind(AssertUnwindSafe(|| {
            connector.check_preconditions(&record.intent, authorization.now)
        })) {
            Ok(Ok(report)) => report,
            Ok(Err(_)) | Err(_) => {
                return self.finalize_observation(
                    record,
                    attempt,
                    receipt_id,
                    event_id,
                    authorization.actor_id.clone(),
                    authorization.now,
                    DispatchObservation::Unknown {
                        evidence_digest: connector_failure,
                        remote_operation_id: None,
                    },
                );
            }
        };
        if !preconditions.satisfied {
            return self.finalize_without_send(
                record,
                attempt,
                receipt_id,
                event_id,
                authorization,
                b"precondition-failed",
            );
        }
        // Consume connector-entry ownership in the same durable repository that owns the
        // attempt. The transition to Unknown is deliberate: after this commit a crash may have
        // happened immediately before or after the remote call, so recovery must reconcile and
        // must never blindly recreate another sending permit.
        let record =
            self.acquire_dispatch_ownership(&record, &permit, receipt_id.clone(), authorization)?;
        let context = DispatchContext {
            intent: &record.intent,
            attempt_id: &attempt.attempt_id,
            fencing_token: attempt.fencing_token,
            request_digest: &attempt.request_digest,
            deadline: attempt.deadline,
            seal: KernelDispatchContextSeal,
        };
        context.verify_kernel_seal();
        let observation = catch_unwind(AssertUnwindSafe(|| connector.dispatch(&context)))
            .ok()
            .and_then(Result::ok)
            .unwrap_or(DispatchObservation::Unknown {
                evidence_digest: connector_failure,
                remote_operation_id: None,
            });
        self.finalize_observation(
            record,
            attempt,
            receipt_id,
            event_id,
            authorization.actor_id.clone(),
            authorization.now,
            observation,
        )
    }

    /// Converts a stale durable in-flight attempt to explicit `Unknown` after restart.
    pub fn recover_inflight(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        actor_id: RecordId,
        now: UtcTimestamp,
        evidence: ContentDigest,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if record.state != EffectState::Dispatching {
            return Err(EffectError::new(EffectErrorCode::InvalidTransition));
        }
        let mut next = record.clone();
        if let Some(outbox) = &mut next.outbox {
            outbox.state = EffectOutboxState::Completed;
        }
        next = transition(
            next,
            EffectState::Unknown,
            actor_id,
            event_id,
            evidence,
            now,
        )?;
        self.persist_next(&record, &next, None)
    }

    fn acquire_dispatch_ownership(
        &self,
        record: &DurableEffectRecord,
        permit: &DispatchPermit,
        ownership_event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        verify_permit(record, permit)?;
        let attempt = record
            .attempts
            .last()
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let ownership_digest = payload_digest(
            b"dispatch-connector-entry",
            &(
                &record.intent.effect_id,
                &attempt.attempt_id,
                attempt.fencing_token,
                &attempt.request_digest,
            ),
        )?;
        let mut next = record.clone();
        if let Some(outbox) = &mut next.outbox {
            outbox.state = EffectOutboxState::Completed;
        }
        next = transition(
            next,
            EffectState::Unknown,
            authorization.actor_id.clone(),
            ownership_event_id,
            ownership_digest.clone(),
            authorization.now,
        )?;
        let identity = IdempotencyIdentity::new(
            format!(
                "effect-dispatch-owner:{}:{}",
                record.intent.effect_id.as_str(),
                attempt.attempt_id.as_str()
            ),
            record.intent.idempotency_key.clone(),
            ownership_digest,
        )
        .map_err(map_store_error)?;
        self.persist_next_exclusive(record, &next, identity)
    }

    /// Authorizes a retry only for descriptor-verified same-key remote idempotency.
    pub fn authorize_idempotent_retry(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if record.state != EffectState::Unknown || !authorization.permits_dispatch(&record.intent) {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        if dispatch_ownership_unreceipted(&record)?
            && record
                .attempts
                .last()
                .is_some_and(|attempt| authorization.now < attempt.deadline)
        {
            return Err(EffectError::new(EffectErrorCode::UnsafeRetry));
        }
        let descriptor = self.connector_descriptor(&record.intent.connector)?;
        let operation = descriptor
            .operation(&record.intent.operation)
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        if !operation.same_key_idempotent
            || !matches!(
                record.intent.retry_policy,
                RetryPolicy::SameKeyIdempotent { .. }
            )
        {
            return Err(EffectError::new(EffectErrorCode::UnsafeRetry));
        }
        let next = transition(
            record.clone(),
            EffectState::AuthorizedForRetry,
            authorization.actor_id.clone(),
            event_id,
            stable_marker(b"same-key-idempotent-retry")?,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Reconciles an explicit unknown without performing another dispatch.
    pub fn reconcile(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        report_id: RecordId,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if record.state != EffectState::Unknown || !authorization.permits_reconciliation() {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        if dispatch_ownership_unreceipted(&record)?
            && record
                .attempts
                .last()
                .is_some_and(|attempt| authorization.now < attempt.deadline)
        {
            return Err(EffectError::new(EffectErrorCode::InvalidTransition));
        }
        let attempt = record
            .attempts
            .last()
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let connector = self.connector(&record.intent.connector)?;
        self.verify_connector_descriptor(&record.intent.connector, &connector)?;
        let descriptor = self.connector_descriptor(&record.intent.connector)?;
        let operation = descriptor
            .operation(&record.intent.operation)
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        if !operation.supports_reconciliation {
            return Err(EffectError::new(EffectErrorCode::UnsafeRetry));
        }
        let context = DispatchContext {
            intent: &record.intent,
            attempt_id: &attempt.attempt_id,
            fencing_token: attempt.fencing_token,
            request_digest: &attempt.request_digest,
            deadline: attempt.deadline,
            seal: KernelDispatchContextSeal,
        };
        context.verify_kernel_seal();
        let fallback_window_end =
            bounded_backoff_end(authorization.now, descriptor.maximum_dispatch_nanos)?;
        let reconcile_failure = stable_marker(b"reconciler-panic-error-or-invalid-response")?;
        let observation = catch_unwind(AssertUnwindSafe(|| connector.reconcile(&context)))
            .ok()
            .and_then(Result::ok)
            .unwrap_or(ReconcileObservation::Inconclusive {
                evidence_digest: reconcile_failure.clone(),
                certainty_window_end: fallback_window_end,
            });
        let (outcome, evidence, certainty_window_end, target) = match observation {
            ReconcileObservation::ConfirmedSuccess(evidence) => (
                ReconciliationOutcome::ConfirmedSuccess,
                evidence,
                None,
                EffectState::Succeeded,
            ),
            ReconcileObservation::ConfirmedFailure(evidence) => (
                ReconciliationOutcome::ConfirmedFailure,
                evidence,
                None,
                EffectState::Failed,
            ),
            ReconcileObservation::ProvenNotExecuted(evidence) => {
                let target = if matches!(record.intent.retry_policy, RetryPolicy::Never) {
                    EffectState::Unknown
                } else {
                    EffectState::AuthorizedForRetry
                };
                (
                    ReconciliationOutcome::ProvenNotExecuted,
                    evidence,
                    None,
                    target,
                )
            }
            ReconcileObservation::Inconclusive {
                mut evidence_digest,
                certainty_window_end,
            } => {
                let certainty_window_end = if certainty_window_end <= authorization.now {
                    evidence_digest = reconcile_failure;
                    fallback_window_end
                } else {
                    certainty_window_end
                };
                (
                    ReconciliationOutcome::Inconclusive,
                    evidence_digest,
                    Some(certainty_window_end),
                    EffectState::Unknown,
                )
            }
        };
        let report = ReconciliationReport {
            schema_version: SchemaVersion::new("cigar.reconciliation-report", 1)
                .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?,
            report_id,
            effect_id: effect_id.clone(),
            attempt_id: Some(attempt.attempt_id.clone()),
            outcome,
            evidence_digests: vec![evidence],
            reconciled_at: authorization.now,
            certainty_window_end,
        };
        report
            .validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        if record.reconciliations.len() >= MAX_EFFECT_RECONCILIATIONS {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        let payload = payload_digest(b"reconciliation", &report)?;
        let mut next = record.clone();
        next.reconciliations.push(report);
        next = transition(
            next,
            target,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Records an explicit audited human resolution without claiming automatic success.
    pub fn manual_resolution(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        resolution_digest: ContentDigest,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        if !authorization.permits_reconciliation() {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        if dispatch_ownership_unreceipted(&record)?
            && record
                .attempts
                .last()
                .is_some_and(|attempt| authorization.now < attempt.deadline)
        {
            return Err(EffectError::new(EffectErrorCode::InvalidTransition));
        }
        let next = transition(
            record.clone(),
            EffectState::ManualResolution,
            authorization.actor_id.clone(),
            event_id,
            resolution_digest,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Links a separately prepared compensation effect and marks the original pending.
    pub fn request_compensation(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        link: CompensationLink,
    ) -> Result<DurableEffectRecord, EffectError> {
        self.request_compensation_with_child_state(
            effect_id,
            expected_version,
            event_id,
            authorization,
            link,
            EffectState::Prepared,
        )
    }

    /// Links a separately prepared *and authorized* compensation effect without dispatching it.
    ///
    /// This entry point is intended for service APIs whose compensation request identifies a
    /// child that has already completed its own explicit authorization workflow. It deliberately
    /// advances only the original effect to `CompensationPending`; dispatching either effect and
    /// advancing the original to `Compensating` remain separate durable transitions.
    pub fn request_authorized_compensation(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        link: CompensationLink,
    ) -> Result<DurableEffectRecord, EffectError> {
        self.request_compensation_with_child_state(
            effect_id,
            expected_version,
            event_id,
            authorization,
            link,
            EffectState::Authorized,
        )
    }

    fn request_compensation_with_child_state(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        link: CompensationLink,
        required_child_state: EffectState,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        link.validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let compensation = record
            .intent
            .compensation
            .as_ref()
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidTransition))?;
        let child = self
            .try_get(&link.compensation_effect_id)?
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))?;
        let descriptor = self.connector_descriptor(&record.intent.connector)?;
        let operation = descriptor
            .operation(&record.intent.operation)
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
        if !operation.supports_compensation
            || link.original_effect_id != *effect_id
            || link.compensation_spec_digest != compensation_spec_digest(compensation)?
            || link.created_at > authorization.now
            || !authorization.permits_dispatch(&record.intent)
            || child.state != required_child_state
            || child.intent.connector != record.intent.connector
            || child.intent.operation != compensation.operation
            || child.intent.arguments_digest != compensation.arguments_digest
            || child.intent.encrypted_arguments != compensation.encrypted_arguments
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let payload = payload_digest(b"compensation-link", &link)?;
        let reservation_digest = payload_digest(
            b"compensation-child-reservation",
            &(
                &link.original_effect_id,
                &link.compensation_effect_id,
                &link.compensation_spec_digest,
            ),
        )?;
        let reservation = IdempotencyIdentity::new(
            format!(
                "effect-compensation-child:{}",
                link.compensation_effect_id.as_str()
            ),
            child.intent.idempotency_key.clone(),
            reservation_digest,
        )
        .map_err(map_store_error)?;
        let mut next = record.clone();
        next.compensation_link = Some(link);
        next = transition(
            next,
            EffectState::CompensationPending,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next_with_identity(&record, &next, None, Some(reservation), false)
    }

    /// Marks the original effect as compensating only after its distinct child is authorized.
    pub fn begin_compensation(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        let link = record
            .compensation_link
            .as_ref()
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidTransition))?;
        let child = self.get(&link.compensation_effect_id)?;
        if record.state != EffectState::CompensationPending
            || !matches!(
                child.state,
                EffectState::Authorized | EffectState::Dispatching
            )
            || !authorization.permits_dispatch(&record.intent)
            || !authorization.permits_dispatch(&child.intent)
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let payload = payload_digest(
            b"compensation-started",
            &(
                &link.compensation_effect_id,
                child.effect_version,
                &child.intent_digest,
            ),
        )?;
        let next = transition(
            record.clone(),
            EffectState::Compensating,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    /// Projects the separately journaled child's definitive or ambiguous compensation outcome.
    pub fn resolve_compensation(
        &self,
        effect_id: &RecordId,
        expected_version: u64,
        event_id: RecordId,
        authorization: &EffectAuthorization,
    ) -> Result<DurableEffectRecord, EffectError> {
        let record = self.get(effect_id)?;
        require_version(&record, expected_version)?;
        let link = record
            .compensation_link
            .as_ref()
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidTransition))?;
        let child = self.get(&link.compensation_effect_id)?;
        if record.state != EffectState::Compensating || !authorization.permits_reconciliation() {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let target = match child.state {
            EffectState::Succeeded | EffectState::Compensated => EffectState::Compensated,
            EffectState::Failed | EffectState::CompensationFailed => {
                EffectState::CompensationFailed
            }
            EffectState::Unknown => EffectState::Unknown,
            _ => return Err(EffectError::new(EffectErrorCode::InvalidTransition)),
        };
        let payload = payload_digest(
            b"compensation-resolved",
            &(
                &link.compensation_effect_id,
                child.effect_version,
                child.state,
                &child.journal.last().map(|event| &event.event_digest),
            ),
        )?;
        let next = transition(
            record.clone(),
            target,
            authorization.actor_id.clone(),
            event_id,
            payload,
            authorization.now,
        )?;
        self.persist_next(&record, &next, None)
    }

    fn finalize_without_send(
        &self,
        record: DurableEffectRecord,
        attempt: EffectAttempt,
        receipt_id: RecordId,
        event_id: RecordId,
        authorization: &EffectAuthorization,
        marker: &[u8],
    ) -> Result<DurableEffectRecord, EffectError> {
        self.finalize_observation(
            record,
            attempt,
            receipt_id,
            event_id,
            authorization.actor_id.clone(),
            authorization.now,
            DispatchObservation::Failed {
                evidence_digest: stable_marker(marker)?,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_observation(
        &self,
        record: DurableEffectRecord,
        attempt: EffectAttempt,
        receipt_id: RecordId,
        event_id: RecordId,
        actor_id: RecordId,
        observed_at: UtcTimestamp,
        observation: DispatchObservation,
    ) -> Result<DurableEffectRecord, EffectError> {
        let (outcome, target, remote_operation_id, response_digest, verification_digest) =
            match observation {
                DispatchObservation::Succeeded {
                    remote_operation_id,
                    response_digest,
                    verification_digest,
                } => (
                    ReceiptOutcome::Succeeded,
                    EffectState::Succeeded,
                    Some(remote_operation_id),
                    Some(response_digest),
                    Some(verification_digest),
                ),
                DispatchObservation::Failed { evidence_digest } => (
                    ReceiptOutcome::Failed,
                    EffectState::Failed,
                    None,
                    None,
                    Some(evidence_digest),
                ),
                DispatchObservation::Unknown {
                    evidence_digest,
                    remote_operation_id,
                } => (
                    ReceiptOutcome::Unknown,
                    EffectState::Unknown,
                    remote_operation_id,
                    None,
                    Some(evidence_digest),
                ),
                DispatchObservation::ProvenNotSent { evidence_digest } => (
                    ReceiptOutcome::Unknown,
                    EffectState::Unknown,
                    None,
                    None,
                    Some(evidence_digest),
                ),
            };
        let receipt = EffectReceipt {
            schema_version: SchemaVersion::new("cigar.effect-receipt", 1)
                .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?,
            receipt_id,
            effect_id: record.intent.effect_id.clone(),
            attempt_id: attempt.attempt_id,
            outcome,
            remote_operation_id,
            protected_response: None,
            response_digest,
            observed_at,
            verification_digest,
        };
        receipt
            .validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let payload = payload_digest(b"receipt", &receipt)?;
        let mut next = record.clone();
        next.receipts.push(receipt);
        if let Some(outbox) = &mut next.outbox {
            outbox.state = EffectOutboxState::Completed;
        }
        next = transition(next, target, actor_id, event_id, payload, observed_at)?;
        self.persist_next(&record, &next, None)
    }

    fn persist_next(
        &self,
        prior: &DurableEffectRecord,
        next: &DurableEffectRecord,
        outbox: Option<OutboxMessage>,
    ) -> Result<DurableEffectRecord, EffectError> {
        self.persist_next_with_identity(prior, next, outbox, None, false)
    }

    fn persist_next_exclusive(
        &self,
        prior: &DurableEffectRecord,
        next: &DurableEffectRecord,
        identity: IdempotencyIdentity,
    ) -> Result<DurableEffectRecord, EffectError> {
        self.persist_next_with_identity(prior, next, None, Some(identity), true)
    }

    fn persist_next_with_identity(
        &self,
        prior: &DurableEffectRecord,
        next: &DurableEffectRecord,
        outbox: Option<OutboxMessage>,
        idempotency: Option<IdempotencyIdentity>,
        replay_is_conflict: bool,
    ) -> Result<DurableEffectRecord, EffectError> {
        verify_record(next)?;
        let event = next
            .journal
            .last()
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        for _attempt in 0..MAX_PERSIST_RETRIES {
            let transaction = self
                .repository
                .begin_read(
                    self.access.clone(),
                    SnapshotSelection::Latest,
                    CancellationToken::default(),
                )
                .map_err(map_store_error)?;
            let revision = transaction.revision();
            let current = transaction
                .get_effect_record(&prior.intent.effect_id)
                .map_err(map_store_error)?
                .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))?;
            if self.decode_record(&current, true)? != *prior {
                return Err(EffectError::new(EffectErrorCode::RevisionConflict));
            }
            let next_envelope = self.encode_record(next)?;
            let mut write = self
                .repository
                .begin_write(self.access.clone(), revision, CancellationToken::default())
                .map_err(map_store_error)?;
            write
                .put_effect_record(next_envelope.clone())
                .map_err(map_store_error)?;
            write
                .append_effect_event(event.clone())
                .map_err(map_store_error)?;
            if let Some(message) = &outbox {
                write
                    .enqueue_outbox(message.clone())
                    .map_err(map_store_error)?;
            }
            match write.commit(idempotency.clone()) {
                Ok(receipt) if replay_is_conflict && receipt.replayed => {
                    return Err(EffectError::new(EffectErrorCode::Unauthorized));
                }
                Ok(_receipt) => {
                    self.observe_envelope(&next_envelope)?;
                    return Ok(next.clone());
                }
                Err(error) if error.code() == StoreErrorCode::RevisionConflict => continue,
                Err(error)
                    if idempotency.is_some() && error.code() == StoreErrorCode::InvalidRecord =>
                {
                    return Err(EffectError::new(EffectErrorCode::IdempotencyCollision));
                }
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(EffectError::new(EffectErrorCode::RevisionConflict))
    }

    fn try_get(&self, effect_id: &RecordId) -> Result<Option<DurableEffectRecord>, EffectError> {
        retry_latest_checkpoint_read(|| self.try_get_at(effect_id, SnapshotSelection::Latest))
    }

    fn try_get_at(
        &self,
        effect_id: &RecordId,
        selection: SnapshotSelection,
    ) -> Result<Option<DurableEffectRecord>, EffectError> {
        let observe_latest = matches!(selection, SnapshotSelection::Latest);
        let transaction = self
            .repository
            .begin_read(self.access.clone(), selection, CancellationToken::default())
            .map_err(map_store_error)?;
        let Some(envelope) = transaction
            .get_effect_record(effect_id)
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        let record = self.decode_record(&envelope, observe_latest)?;
        let events = transaction.get_effect(effect_id).map_err(map_store_error)?;
        if events != record.journal {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
        verify_record(&record)?;
        Ok(Some(record))
    }

    fn encode_record(
        &self,
        record: &DurableEffectRecord,
    ) -> Result<EffectRecordEnvelope, EffectError> {
        let canonical_record = serde_json::to_vec(record)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let seal = self
            .authenticator
            .seal(self.access.tenant_id(), &canonical_record)?;
        seal.validate()?;
        let authenticated = AuthenticatedEffectRecord {
            schema_version: AUTHENTICATED_RECORD_SCHEMA.to_owned(),
            record: record.clone(),
            seal,
        };
        let bytes = serde_json::to_vec(&authenticated)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let record_digest = raw_multihash(&bytes)?;
        EffectRecordEnvelope::new(
            record.intent.effect_id.clone(),
            record.effect_version,
            record_digest,
            bytes,
        )
        .map_err(map_store_error)
    }

    fn decode_record(
        &self,
        envelope: &EffectRecordEnvelope,
        observe_latest: bool,
    ) -> Result<DurableEffectRecord, EffectError> {
        let authenticated = decode_authenticated_effect_record(envelope)?;
        let canonical_record = serde_json::to_vec(&authenticated.record)
            .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
        self.authenticator.verify(
            self.access.tenant_id(),
            &canonical_record,
            &authenticated.seal,
        )?;
        if observe_latest {
            self.authenticator.observe_latest(
                self.access.tenant_id(),
                &authenticated.record.intent.effect_id,
                &authenticated.record.intent_digest,
                authenticated.record.effect_version,
                authenticated.seal.authenticator(),
            )?;
        }
        Ok(authenticated.record)
    }

    fn observe_envelope(&self, envelope: &EffectRecordEnvelope) -> Result<(), EffectError> {
        let _record = self.decode_record(envelope, true)?;
        Ok(())
    }

    fn latest_revision(&self) -> Result<StoreRevision, EffectError> {
        self.repository
            .begin_read(
                self.access.clone(),
                SnapshotSelection::Latest,
                CancellationToken::default(),
            )
            .map(|transaction| transaction.revision())
            .map_err(map_store_error)
    }

    fn connector(&self, name: &str) -> Result<Arc<dyn EffectConnector>, EffectError> {
        self.connectors
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(name)
            .map(|connector| Arc::clone(&connector.implementation))
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))
    }

    fn connector_descriptor(&self, name: &str) -> Result<ConnectorDescriptor, EffectError> {
        self.connectors
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(name)
            .map(|connector| connector.descriptor.clone())
            .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))
    }

    fn verify_connector_descriptor(
        &self,
        name: &str,
        connector: &Arc<dyn EffectConnector>,
    ) -> Result<(), EffectError> {
        let registered = self.connector_descriptor(name)?;
        let current = catch_unwind(AssertUnwindSafe(|| connector.descriptor()))
            .map_err(|_panic| EffectError::new(EffectErrorCode::Unavailable))?;
        current.validate()?;
        if current == registered {
            Ok(())
        } else {
            Err(EffectError::new(EffectErrorCode::Unavailable))
        }
    }
}

fn decode_authenticated_effect_record(
    envelope: &EffectRecordEnvelope,
) -> Result<AuthenticatedEffectRecord, EffectError> {
    if raw_multihash(envelope.bytes())? != envelope.record_digest {
        return Err(EffectError::new(EffectErrorCode::CorruptJournal));
    }
    let authenticated: AuthenticatedEffectRecord = serde_json::from_slice(envelope.bytes())
        .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
    if authenticated.schema_version != AUTHENTICATED_RECORD_SCHEMA
        || authenticated.record.intent.effect_id != envelope.effect_id
        || authenticated.record.effect_version != envelope.effect_version
        || serde_json::to_vec(&authenticated)
            .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?
            != envelope.bytes()
    {
        return Err(EffectError::new(EffectErrorCode::CorruptJournal));
    }
    authenticated
        .seal
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
    Ok(authenticated)
}

fn verify_approval(
    record: &DurableEffectRecord,
    approval: &EffectApproval,
    now: UtcTimestamp,
) -> Result<(), EffectError> {
    approval
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    if approval.effect_id != record.intent.effect_id
        || approval.intent_digest != record.intent_digest
        || approval.target_digest != effect_target_digest(&record.intent.target)?
        || approval.risk != record.intent.risk
        || approval.bundle_id != record.intent.bundle_id
        || now < approval.approved_at
        || now >= approval.expires_at
        || (matches!(record.intent.risk, RiskLevel::High | RiskLevel::Critical)
            && approval.kind != ApprovalKind::Human)
    {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    } else {
        Ok(())
    }
}

fn validate_retry_claim(
    record: &DurableEffectRecord,
    same_key_idempotent: bool,
) -> Result<(), EffectError> {
    match record.state {
        EffectState::Authorized if record.attempts.is_empty() => Ok(()),
        EffectState::AuthorizedForRetry => match record.intent.retry_policy {
            RetryPolicy::Never => Err(EffectError::new(EffectErrorCode::UnsafeRetry)),
            RetryPolicy::SameKeyIdempotent { max_attempts }
                if same_key_idempotent && usize::from(max_attempts) > record.attempts.len() =>
            {
                Ok(())
            }
            RetryPolicy::ReconcileBeforeRetry
                if record.reconciliations.last().is_some_and(|report| {
                    report.outcome == ReconciliationOutcome::ProvenNotExecuted
                }) =>
            {
                Ok(())
            }
            RetryPolicy::SameKeyIdempotent { .. } | RetryPolicy::ReconcileBeforeRetry => {
                Err(EffectError::new(EffectErrorCode::UnsafeRetry))
            }
        },
        EffectState::Authorized => Err(EffectError::new(EffectErrorCode::CorruptJournal)),
        _ => Err(EffectError::new(EffectErrorCode::InvalidTransition)),
    }
}

fn require_version(record: &DurableEffectRecord, expected: u64) -> Result<(), EffectError> {
    if record.effect_version == expected {
        Ok(())
    } else {
        Err(EffectError::new(EffectErrorCode::RevisionConflict))
    }
}

fn transition(
    mut record: DurableEffectRecord,
    target: EffectState,
    actor_id: RecordId,
    event_id: RecordId,
    payload_digest: ContentDigest,
    recorded_at: UtcTimestamp,
) -> Result<DurableEffectRecord, EffectError> {
    if !record.state.can_transition_to(target)
        || recorded_at < record.intent.created_at
        || record
            .journal
            .last()
            .is_some_and(|event| recorded_at < event.recorded_at)
    {
        return Err(EffectError::new(EffectErrorCode::InvalidTransition));
    }
    let sequence = record
        .effect_version
        .checked_add(1)
        .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
    let previous_event_digest = record
        .journal
        .last()
        .map(|event| event.event_digest.clone());
    let event_digest = journal_digest(
        &event_id,
        &record.intent.effect_id,
        sequence,
        record.effect_version,
        record.state,
        target,
        &actor_id,
        &payload_digest,
        previous_event_digest.as_ref(),
        recorded_at,
    )?;
    let event = EffectJournalEvent {
        schema_version: SchemaVersion::new("cigar.effect-journal-event", 1)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?,
        event_id,
        effect_id: record.intent.effect_id.clone(),
        sequence,
        expected_effect_version: record.effect_version,
        from_state: record.state,
        to_state: target,
        actor_id,
        payload_digest,
        previous_event_digest,
        event_digest,
        recorded_at,
    };
    event
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidTransition))?;
    record.journal.push(event);
    record.state = target;
    record.effect_version = sequence;
    Ok(record)
}

fn verify_record(record: &DurableEffectRecord) -> Result<(), EffectError> {
    record
        .intent
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
    if effect_intent_digest(&record.intent)? != record.intent_digest
        || record
            .approval
            .as_ref()
            .map(effect_approval_digest)
            .transpose()?
            != record.approval_digest
        || usize::try_from(record.effect_version).ok() != Some(record.journal.len())
        || record.state
            != record
                .journal
                .last()
                .map_or(EffectState::Prepared, |event| event.to_state)
        || record.attempts.len() > MAX_EFFECT_ATTEMPTS
        || record.reconciliations.len() > MAX_EFFECT_RECONCILIATIONS
    {
        return Err(EffectError::new(EffectErrorCode::CorruptJournal));
    }
    if let Some(approval) = &record.approval {
        approval
            .validate()
            .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
        if approval.effect_id != record.intent.effect_id
            || approval.intent_digest != record.intent_digest
            || approval.target_digest != effect_target_digest(&record.intent.target)?
            || approval.risk != record.intent.risk
            || approval.bundle_id != record.intent.bundle_id
            || approval.approved_at < record.intent.created_at
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
    }
    let mut previous: Option<&EffectJournalEvent> = None;
    for event in &record.journal {
        let expected_sequence = match previous {
            Some(prior) => prior
                .sequence
                .checked_add(1)
                .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?,
            None => 1,
        };
        let expected_version = event
            .sequence
            .checked_sub(1)
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let expected_from = previous.map_or(EffectState::Prepared, |prior| prior.to_state);
        let expected_previous = previous.map(|prior| &prior.event_digest);
        if event.validate().is_err()
            || event.effect_id != record.intent.effect_id
            || event.recorded_at < record.intent.created_at
            || previous.is_some_and(|prior| event.recorded_at < prior.recorded_at)
            || event.sequence != expected_sequence
            || event.expected_effect_version != expected_version
            || event.from_state != expected_from
            || event.previous_event_digest.as_ref() != expected_previous
            || !event.from_state.can_transition_to(event.to_state)
            || event.event_digest
                != journal_digest(
                    &event.event_id,
                    &event.effect_id,
                    event.sequence,
                    event.expected_effect_version,
                    event.from_state,
                    event.to_state,
                    &event.actor_id,
                    &event.payload_digest,
                    event.previous_event_digest.as_ref(),
                    event.recorded_at,
                )?
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
        previous = Some(event);
    }
    let dispatch_event_count = record
        .journal
        .iter()
        .filter(|event| event.to_state == EffectState::Dispatching)
        .count();
    if dispatch_event_count != record.attempts.len() {
        return Err(EffectError::new(EffectErrorCode::CorruptJournal));
    }
    let mut attempt_ids = BTreeMap::new();
    for (index, attempt) in record.attempts.iter().enumerate() {
        let expected_number = index
            .checked_add(1)
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        let expected_fence = u64::try_from(expected_number)
            .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))?;
        if attempt.validate().is_err()
            || usize::from(attempt.attempt_number)
                != index
                    .checked_add(1)
                    .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?
            || attempt.fencing_token != expected_fence
            || attempt.effect_id != record.intent.effect_id
            || attempt.request_digest != record.intent_digest
            || attempt.started_at < record.intent.created_at
            || attempt.started_at >= record.intent.expires_at
            || attempt.deadline > record.intent.expires_at
            || attempt_ids
                .insert(attempt.attempt_id.clone(), attempt.attempt_number)
                .is_some()
            || index > 0
                && record
                    .attempts
                    .get(index.saturating_sub(1))
                    .is_some_and(|prior| prior.fencing_token >= attempt.fencing_token)
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
    }
    let mut seen_attempts = BTreeMap::new();
    for receipt in &record.receipts {
        let matching_attempt = record
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == receipt.attempt_id);
        if receipt.validate().is_err()
            || receipt.effect_id != record.intent.effect_id
            || matching_attempt.is_none()
            || matching_attempt.is_some_and(|attempt| receipt.observed_at < attempt.started_at)
            || seen_attempts
                .insert(receipt.attempt_id.clone(), receipt.receipt_id.clone())
                .is_some()
            || !record.journal.iter().any(|event| {
                payload_digest(b"receipt", receipt)
                    .is_ok_and(|digest| event.payload_digest == digest)
            })
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
    }
    let mut reconciliation_ids = BTreeMap::new();
    for report in &record.reconciliations {
        if report.validate().is_err()
            || report.effect_id != record.intent.effect_id
            || report.attempt_id.as_ref().is_none_or(|attempt_id| {
                !record
                    .attempts
                    .iter()
                    .any(|attempt| &attempt.attempt_id == attempt_id)
            })
            || reconciliation_ids
                .insert(report.report_id.clone(), report.reconciled_at)
                .is_some()
            || !record.journal.iter().any(|event| {
                payload_digest(b"reconciliation", report)
                    .is_ok_and(|digest| event.payload_digest == digest)
            })
        {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
    }
    if let Some(link) = &record.compensation_link
        && (link.validate().is_err()
            || link.original_effect_id != record.intent.effect_id
            || record
                .intent
                .compensation
                .as_ref()
                .is_none_or(|compensation| {
                    !compensation_spec_digest(compensation)
                        .is_ok_and(|digest| digest == link.compensation_spec_digest)
                }))
    {
        return Err(EffectError::new(EffectErrorCode::CorruptJournal));
    }
    match (&record.outbox, record.state) {
        (None, EffectState::Dispatching) => {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
        (Some(outbox), state) => {
            let Some(attempt) = record.attempts.last() else {
                return Err(EffectError::new(EffectErrorCode::CorruptJournal));
            };
            let expected_state = if state == EffectState::Dispatching {
                EffectOutboxState::Claimed
            } else {
                EffectOutboxState::Completed
            };
            if outbox.attempt_id != attempt.attempt_id
                || outbox.fencing_token != attempt.fencing_token
                || outbox.state != expected_state
                || outbox.state == EffectOutboxState::Pending
            {
                return Err(EffectError::new(EffectErrorCode::CorruptJournal));
            }
        }
        (None, _) => {}
    }
    Ok(())
}

/// Computes the canonical semantic identity bound to an effect intent and idempotency key.
pub fn effect_intent_digest(intent: &EffectIntent) -> Result<ContentDigest, EffectError> {
    intent
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    let encoded = semantic_multihash_v1(SemanticEnvelopeProfile::Effect, intent)
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    ContentDigest::new(encoded).map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))
}

/// Computes the exact target digest that an approval must bind.
pub fn effect_target_digest(target: &str) -> Result<ContentDigest, EffectError> {
    if target.is_empty() || target.len() > 256 || target.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(EffectError::new(EffectErrorCode::InvalidInput));
    }
    payload_digest(b"effect-target", &target)
}

/// Computes the domain-separated digest stored beside an exact approval.
pub fn effect_approval_digest(approval: &EffectApproval) -> Result<ContentDigest, EffectError> {
    approval
        .validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    payload_digest(b"effect-approval", approval)
}

/// Computes the digest linking a separate compensation effect to its original specification.
pub fn compensation_spec_digest(
    compensation: &CompensationSpec,
) -> Result<ContentDigest, EffectError> {
    if compensation.operation.is_empty()
        || compensation.operation.len() > 256
        || compensation
            .operation
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(EffectError::new(EffectErrorCode::InvalidInput));
    }
    payload_digest(b"compensation-spec", compensation)
}

#[allow(clippy::too_many_arguments)]
fn journal_digest(
    event_id: &RecordId,
    effect_id: &RecordId,
    sequence: u64,
    expected_effect_version: u64,
    from_state: EffectState,
    to_state: EffectState,
    actor_id: &RecordId,
    payload_digest: &ContentDigest,
    previous_event_digest: Option<&ContentDigest>,
    recorded_at: UtcTimestamp,
) -> Result<ContentDigest, EffectError> {
    payload_digest_fn(
        b"effect-journal-event",
        &(
            event_id,
            effect_id,
            sequence,
            expected_effect_version,
            from_state,
            to_state,
            actor_id,
            payload_digest,
            previous_event_digest.map_or("", ContentDigest::as_str),
            recorded_at,
        ),
    )
}

fn payload_digest(domain: &[u8], value: &impl Serialize) -> Result<ContentDigest, EffectError> {
    payload_digest_fn(domain, value)
}

fn payload_digest_fn(domain: &[u8], value: &impl Serialize) -> Result<ContentDigest, EffectError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-EFFECT-KERNEL\0v1\0");
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    digest_to_multihash(hasher.finalize().into())
}

fn default_process_authenticator() -> Arc<dyn EffectRecordAuthenticator> {
    static AUTHENTICATOR: OnceLock<Arc<ProcessEffectAuthenticator>> = OnceLock::new();
    AUTHENTICATOR
        .get_or_init(|| Arc::new(ProcessEffectAuthenticator::process_local()))
        .clone()
}

fn process_random_key() -> Option<[u8; 32]> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).ok()?;
    Some(key)
}

fn keyed_record_authenticator(
    key: &[u8; 32],
    tenant_id: &RecordId,
    canonical_record: &[u8],
) -> Result<ContentDigest, EffectError> {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for ((inner, outer), byte) in inner_pad.iter_mut().zip(&mut outer_pad).zip(key) {
        *inner ^= byte;
        *outer ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(b"CIGAR-EFFECT-RECORD-AUTHENTICATOR\0v1\0");
    inner.update(
        u64::try_from(tenant_id.as_str().len())
            .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    inner.update(tenant_id.as_str().as_bytes());
    inner.update(
        u64::try_from(canonical_record.len())
            .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    inner.update(canonical_record);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    digest_to_multihash(outer.finalize().into())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn raw_multihash(bytes: &[u8]) -> Result<ContentDigest, EffectError> {
    digest_to_multihash(Sha256::digest(bytes).into())
}

fn digest_to_multihash(digest: [u8; 32]) -> Result<ContentDigest, EffectError> {
    let mut encoded = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))
}

fn stable_marker(marker: &[u8]) -> Result<ContentDigest, EffectError> {
    raw_multihash(marker)
}

fn bounded_backoff_end(now: UtcTimestamp, backoff_nanos: u64) -> Result<UtcTimestamp, EffectError> {
    let value = now
        .unix_nanos()
        .checked_add(i128::from(backoff_nanos))
        .ok_or_else(|| EffectError::new(EffectErrorCode::LimitExceeded))?;
    UtcTimestamp::from_unix_nanos(value)
        .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))
}

fn permit_seal(
    effect_id: &RecordId,
    attempt_id: &RecordId,
    fencing_token: u64,
    effect_version: u64,
    request_digest: &ContentDigest,
) -> Result<ContentDigest, EffectError> {
    payload_digest(
        b"dispatch-permit",
        &(
            effect_id,
            attempt_id,
            fencing_token,
            effect_version,
            request_digest,
        ),
    )
}

fn verify_permit(record: &DurableEffectRecord, permit: &DispatchPermit) -> Result<(), EffectError> {
    let outbox = record
        .outbox
        .as_ref()
        .ok_or_else(|| EffectError::new(EffectErrorCode::Unauthorized))?;
    if record.state != EffectState::Dispatching
        || record.effect_version != permit.effect_version
        || record.intent.effect_id != permit.effect_id
        || outbox.attempt_id != permit.attempt_id
        || outbox.fencing_token != permit.fencing_token
        || outbox.state != EffectOutboxState::Claimed
        || permit.request_digest != record.intent_digest
        || permit.seal
            != permit_seal(
                &permit.effect_id,
                &permit.attempt_id,
                permit.fencing_token,
                permit.effect_version,
                &permit.request_digest,
            )?
    {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    } else {
        Ok(())
    }
}

fn dispatch_ownership_unreceipted(record: &DurableEffectRecord) -> Result<bool, EffectError> {
    if record.state != EffectState::Unknown {
        return Ok(false);
    }
    let Some(attempt) = record.attempts.last() else {
        return Ok(false);
    };
    if record
        .receipts
        .iter()
        .any(|receipt| receipt.attempt_id == attempt.attempt_id)
    {
        return Ok(false);
    }
    let expected = payload_digest(
        b"dispatch-connector-entry",
        &(
            &record.intent.effect_id,
            &attempt.attempt_id,
            attempt.fencing_token,
            &attempt.request_digest,
        ),
    )?;
    Ok(record.journal.last().is_some_and(|event| {
        event.from_state == EffectState::Dispatching
            && event.to_state == EffectState::Unknown
            && event.payload_digest == expected
    }))
}

fn map_store_error(error: StoreError) -> EffectError {
    let code = match error.code() {
        StoreErrorCode::NotFound => EffectErrorCode::NotFound,
        StoreErrorCode::RevisionConflict => EffectErrorCode::RevisionConflict,
        StoreErrorCode::InvalidContext | StoreErrorCode::InvalidRecord => {
            EffectErrorCode::InvalidInput
        }
        StoreErrorCode::LimitExceeded => EffectErrorCode::LimitExceeded,
        StoreErrorCode::Cancelled => EffectErrorCode::Cancelled,
        StoreErrorCode::MixedSnapshot
        | StoreErrorCode::InjectedAbort
        | StoreErrorCode::Unavailable => EffectErrorCode::Unavailable,
    };
    EffectError::new(code)
}

fn retry_latest_checkpoint_read<T>(
    mut read: impl FnMut() -> Result<T, EffectError>,
) -> Result<T, EffectError> {
    // The repository snapshot and the external checkpoint are independently locked. A writer can
    // advance the checkpoint after this reader opens a valid, now-stale snapshot. Only that
    // explicit revision conflict is retryable; cryptographic or journal failures return unchanged.
    for attempt in 0..MAX_LATEST_READ_RETRIES {
        match read() {
            Err(error)
                if error.code() == EffectErrorCode::RevisionConflict
                    && attempt + 1 < MAX_LATEST_READ_RETRIES =>
            {
                std::thread::yield_now();
            }
            Err(error) if error.code() == EffectErrorCode::RevisionConflict => {
                return Err(EffectError::new(EffectErrorCode::CorruptJournal));
            }
            result => return result,
        }
    }
    Err(EffectError::new(EffectErrorCode::CorruptJournal))
}

#[cfg(test)]
mod latest_checkpoint_read_tests {
    use super::{MAX_LATEST_READ_RETRIES, retry_latest_checkpoint_read};
    use crate::{EffectError, EffectErrorCode};
    use std::cell::Cell;

    #[test]
    fn stale_checkpoint_snapshot_retries_the_complete_latest_read() -> Result<(), EffectError> {
        let calls = Cell::new(0_usize);
        let value = retry_latest_checkpoint_read(|| {
            let observed = calls.get();
            calls.set(observed + 1);
            if observed == 0 {
                Err(EffectError::new(EffectErrorCode::RevisionConflict))
            } else {
                Ok(7_u8)
            }
        })?;
        assert_eq!(value, 7);
        assert_eq!(calls.get(), 2);
        Ok(())
    }

    #[test]
    fn persistent_checkpoint_mismatch_remains_an_integrity_failure() {
        let calls = Cell::new(0_usize);
        let error = retry_latest_checkpoint_read::<()>(|| {
            calls.set(calls.get() + 1);
            Err(EffectError::new(EffectErrorCode::RevisionConflict))
        });
        assert_eq!(
            error.err().map(EffectError::code),
            Some(EffectErrorCode::CorruptJournal)
        );
        assert_eq!(calls.get(), MAX_LATEST_READ_RETRIES);
    }

    #[test]
    fn cryptographic_corruption_is_never_retried() {
        let calls = Cell::new(0_usize);
        let error = retry_latest_checkpoint_read::<()>(|| {
            calls.set(calls.get() + 1);
            Err(EffectError::new(EffectErrorCode::CorruptJournal))
        });
        assert_eq!(
            error.err().map(EffectError::code),
            Some(EffectErrorCode::CorruptJournal)
        );
        assert_eq!(calls.get(), 1);
    }
}
