//! Signed handoff creation, recipient acceptance, subscriptions, and child-result merge.

use crate::{ContextSpaceService, ProposedMutation, ResourceKey, SpaceError};
use cigar_canon::{parse_strict_json, to_deterministic_cbor};
use cigar_crypto::{
    KeyAlgorithm, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest, SignatureVerification,
};
use cigar_policy::EffectiveCapabilities;
use cigar_protocol::{
    Budget, Capability, ContentDigest, ContextSpaceId, CoordinationEvent, CoordinationEventKind,
    CoordinationTopic, ExpectedRevision, ExtensionMap, HandoffAcceptance, HandoffCapsule,
    HandoffDelta, HandoffReferences, OverlayMutation, RecipientSelector, RecordId, SchemaVersion,
    UtcTimestamp, Validate, VersionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

const HANDOFF_SIGNATURE_PURPOSE: &str = "cigar.handoff.v1";

/// Stable content-free handoff failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// A capsule, request, or child result is malformed.
    InvalidInput,
    /// Signature, digest, or key metadata verification failed.
    InvalidSignature,
    /// Current audience, recipient, role, authority, project, or target denies use.
    Forbidden,
    /// The capsule, principal, or grant is currently revoked.
    Revoked,
    /// A one-time nonce or acceptance identity was already consumed.
    Replay,
    /// The capsule is not currently within its signed time interval.
    Expired,
    /// A bounded collection or arithmetic limit was exceeded.
    LimitExceeded,
    /// Signing, compilation, or serialization was unavailable.
    Unavailable,
    /// The caller did not hold the exact current handoff revision.
    RevisionConflict,
    /// Parent overlay publication or merge failed.
    Merge,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "handoff operation failed: {self:?}")
    }
}

impl std::error::Error for HandoffError {}

/// Inputs fixed before a handoff is previewed and signed.
#[derive(Clone, Debug)]
pub struct CreateHandoffRequest {
    /// Unique capsule identity.
    pub handoff_id: RecordId,
    /// Verified issuer authority.
    pub issuer_effective: EffectiveCapabilities,
    /// Intended principal or role.
    pub recipient: RecipientSelector,
    /// Bounded task statement.
    pub task: String,
    /// Bounded acceptance criteria.
    pub acceptance_criteria: Vec<String>,
    /// Requested project scope.
    pub requested_projects: BTreeSet<RecordId>,
    /// Requested delegated operations.
    pub requested_capabilities: BTreeSet<Capability>,
    /// Projects currently allowed by handoff policy.
    pub policy_allowed_projects: BTreeSet<RecordId>,
    /// Capabilities currently allowed by handoff policy.
    pub policy_allowed_capabilities: BTreeSet<Capability>,
    /// Recipient compilation ceiling.
    pub budget: Budget,
    /// Requested bounded topics.
    pub topics: BTreeSet<CoordinationTopic>,
    /// Typed references; there is no transcript field.
    pub references: HandoffReferences,
    /// Issuer bundle at creation.
    pub bundle_id: VersionId,
    /// Signed runtime audience.
    pub audience: String,
    /// Creation time.
    pub created_at: UtcTimestamp,
    /// Exclusive expiry.
    pub expires_at: UtcTimestamp,
    /// Caller-generated replay-protection nonce.
    pub nonce: Vec<u8>,
    /// Whether multiple acceptances are permitted.
    pub reusable: bool,
    /// Active issuer signing key.
    pub issuer_key_ref: KeyRef,
}

/// Exact disclosure and attenuation preview before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffCreationPreview {
    /// Projects retained after issuer and policy intersection.
    pub accepted_projects: Vec<RecordId>,
    /// Requested projects rejected by current authority or policy.
    pub rejected_projects: Vec<RecordId>,
    /// Capabilities retained after issuer and policy intersection.
    pub delegated_capabilities: Vec<Capability>,
    /// Requested capabilities rejected during creation.
    pub rejected_capabilities: Vec<Capability>,
    /// Number of typed references, excluding any transcript.
    pub reference_count: usize,
}

/// Recipient-side inputs that are rechecked independently of issuer claims.
#[derive(Clone, Debug)]
pub struct AcceptHandoffRequest {
    /// Signed capsule.
    pub capsule: HandoffCapsule,
    /// Exact current authoritative handoff revision.
    pub expected_revision: ExpectedRevision,
    /// Unique receipt identity.
    pub acceptance_id: RecordId,
    /// Authenticated recipient.
    pub recipient_id: RecordId,
    /// Current authenticated recipient roles.
    pub recipient_roles: BTreeSet<String>,
    /// Exact current runtime audience.
    pub expected_audience: String,
    /// Tenant used for signing-key verification.
    pub tenant: String,
    /// Current time.
    pub now: UtcTimestamp,
    /// Current recipient effective authority.
    pub recipient_effective: EffectiveCapabilities,
    /// Capabilities currently allowed by acceptance policy.
    pub policy_allowed_capabilities: BTreeSet<Capability>,
    /// Current policy decision digest.
    pub policy_digest: ContentDigest,
    /// Principals currently revoked.
    pub revoked_principals: BTreeSet<RecordId>,
    /// Signing-key identifiers currently revoked independently of historical verification.
    pub revoked_key_ids: BTreeSet<String>,
    /// Whether the recipient target/model restriction currently permits compilation.
    pub target_allowed: bool,
    /// Acceptance timestamp, normally equal to `now`.
    pub accepted_at: UtcTimestamp,
}

/// Inputs for an issuer-authorized, optimistic handoff revocation.
#[derive(Clone, Debug)]
pub struct RevokeHandoffRequest {
    /// Exact capsule to revoke.
    pub handoff_id: RecordId,
    /// Exact current handoff revision.
    pub expected_revision: ExpectedRevision,
    /// Authenticated actor, which must be the capsule issuer.
    pub actor_id: RecordId,
    /// Current policy decision digest authorizing revocation.
    pub policy_digest: ContentDigest,
    /// Content-safe digest of the authorized revocation reason or evidence.
    pub reason_digest: ContentDigest,
    /// Revocation decision time.
    pub revoked_at: UtcTimestamp,
    /// Caller-selected immutable coordination event identity.
    pub event_id: RecordId,
}

/// Immutable authoritative handoff revocation record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRevocation {
    /// Revoked capsule identity.
    pub handoff_id: RecordId,
    /// Issuer that authorized the revocation.
    pub issuer_id: RecordId,
    /// Revision committed by this mutation.
    pub revision: u64,
    /// Policy decision used at revocation time.
    pub policy_digest: ContentDigest,
    /// Content-safe digest of the authorized revocation reason or evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_digest: Option<ContentDigest>,
    /// Revocation decision time.
    pub revoked_at: UtcTimestamp,
    /// Stable event emitted for the revocation.
    pub event: CoordinationEvent,
}

/// Inputs for persisting one accepted recipient's immutable child result.
#[derive(Clone, Debug)]
pub struct RecordHandoffResultRequest {
    /// Exact current handoff revision.
    pub expected_revision: ExpectedRevision,
    /// Acceptance receipt that authenticated and scoped this producer.
    pub acceptance_id: RecordId,
    /// Authenticated result producer.
    pub actor_id: RecordId,
    /// Current server-derived project authority for the authenticated producer.
    pub current_project_ids: BTreeSet<RecordId>,
    /// Typed child result proposed against the accepted bundle.
    pub delta: HandoffDelta,
    /// Caller-selected immutable coordination event identity.
    pub event_id: RecordId,
}

/// Immutable child-result persistence receipt and merge input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffResultReceipt {
    /// Exact acceptance that authorized the producer.
    pub acceptance_id: RecordId,
    /// Revision committed by this mutation.
    pub revision: u64,
    /// Complete validated immutable child delta.
    pub delta: HandoffDelta,
    /// Stable event emitted for the result proposal.
    pub event: CoordinationEvent,
}

/// Issuer-visible immutable records required to merge one retained child result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffMergeMaterial {
    /// Signed capsule that authorized the delegation.
    pub capsule: HandoffCapsule,
    /// Exact acceptance that authenticated the result producer.
    pub acceptance: HandoffAcceptance,
    /// Server-sealed authority and compiler provenance retained with the acceptance.
    pub acceptance_authority: HandoffAcceptanceAuthority,
    /// Retained immutable child-result receipt.
    pub result: HandoffResultReceipt,
}

/// Reauthorized input passed to recipient-specific bundle compilation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedHandoffContext {
    /// Authenticated recipient.
    pub recipient_id: RecordId,
    /// Accepted exact project scope.
    pub project_ids: Vec<RecordId>,
    /// Accepted attenuated capabilities.
    pub capabilities: Vec<Capability>,
    /// Available reauthorized typed references.
    pub references: HandoffReferences,
    /// Signed recipient budget ceiling.
    pub budget: Budget,
}

/// Exact server-observed proof that an accepted bundle derives from the signed handoff source.
///
/// This is an internal durable authority record rather than part of the frozen public v1 ABI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientBundleReceipt {
    /// Recipient-specific output bundle persisted in the public acceptance.
    pub bundle_id: VersionId,
    /// Exact signed source bundle from the capsule.
    pub source_bundle_id: VersionId,
    /// Exact retained server-side target plan selected for compilation.
    pub target_plan_id: RecordId,
    /// Immutable service-record version observed for the target plan.
    pub target_plan_revision: u64,
    /// Digest of the exact retained target-plan record.
    pub target_plan_digest: ContentDigest,
    /// Domain-separated proof over source, accepted scope, plan, and output.
    pub derivation_digest: ContentDigest,
}

/// Internal durable acceptance authority used by result and merge authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffAcceptanceAuthority {
    /// Exact accepted projects, capabilities, references, and budget.
    pub accepted: AcceptedHandoffContext,
    /// Compiler provenance sealed into the acknowledgement digest.
    pub compilation: RecipientBundleReceipt,
}

/// Inspection result produced without consuming replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceInspection {
    /// Context safe to pass to the compiler.
    pub context: AcceptedHandoffContext,
    /// Capabilities rejected during recipient reauthorization.
    pub rejected_capabilities: Vec<Capability>,
    /// Capsule references unavailable to the recipient.
    pub unavailable_references: Vec<VersionId>,
    /// Topics that may be subscribed after acceptance.
    pub topics: Vec<CoordinationTopic>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayState {
    acceptance_ids: BTreeSet<RecordId>,
    consumed_one_time_nonces: BTreeSet<Vec<u8>>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffState {
    capsules: BTreeMap<RecordId, HandoffCapsule>,
    #[serde(default)]
    previews: BTreeMap<RecordId, HandoffCreationPreview>,
    #[serde(default)]
    revisions: BTreeMap<RecordId, u64>,
    #[serde(default)]
    revocations: BTreeMap<RecordId, HandoffRevocation>,
    acceptances: BTreeMap<RecordId, HandoffAcceptance>,
    #[serde(default)]
    acceptance_authorities: BTreeMap<RecordId, HandoffAcceptanceAuthority>,
    #[serde(default)]
    results: BTreeMap<RecordId, HandoffResultReceipt>,
    replay: ReplayState,
    subscriptions: BTreeMap<RecordId, Vec<CoordinationTopic>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HandoffSnapshot {
    schema_version: String,
    state: HandoffState,
}

const HANDOFF_SNAPSHOT_SCHEMA: &str = "cigar.handoff-snapshot.v1";

/// Signed handoff service backed by a scoped key provider.
pub struct HandoffService {
    provider: Arc<dyn KeyProvider>,
    state: Mutex<HandoffState>,
}

impl fmt::Debug for HandoffService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandoffService([REDACTED])")
    }
}

impl HandoffService {
    /// Creates a service around a provider that never exports private signing material.
    #[must_use]
    pub fn new(provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            provider,
            state: Mutex::new(HandoffState::default()),
        }
    }

    /// Serializes all capsules, receipts, replay guards, and subscriptions as one strict state.
    pub fn export_snapshot(&self) -> Result<Vec<u8>, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        validate_handoff_state(&state)?;
        serde_json::to_vec(&HandoffSnapshot {
            schema_version: HANDOFF_SNAPSHOT_SCHEMA.to_owned(),
            state: state.clone(),
        })
        .map_err(|_error| HandoffError::Unavailable)
    }

    /// Restores a complete strict snapshot around the supplied scoped key provider.
    pub fn from_snapshot(
        provider: Arc<dyn KeyProvider>,
        bytes: &[u8],
    ) -> Result<Self, HandoffError> {
        parse_strict_json(bytes).map_err(|_error| HandoffError::InvalidInput)?;
        let mut snapshot: HandoffSnapshot =
            serde_json::from_slice(bytes).map_err(|_error| HandoffError::InvalidInput)?;
        if snapshot.schema_version != HANDOFF_SNAPSHOT_SCHEMA {
            return Err(HandoffError::InvalidInput);
        }
        normalize_legacy_handoff_state(&mut snapshot.state);
        validate_handoff_state(&snapshot.state)?;
        Ok(Self {
            provider,
            state: Mutex::new(snapshot.state),
        })
    }

    /// Computes the exact authority and disclosure intersection before signing.
    pub fn preview_creation(
        &self,
        request: &CreateHandoffRequest,
    ) -> Result<HandoffCreationPreview, HandoffError> {
        if !request
            .issuer_effective
            .capabilities
            .contains(&Capability::CreateHandoff)
            || request.created_at >= request.issuer_effective.expires_at
            || request.expires_at <= request.created_at
            || request.expires_at > request.issuer_effective.expires_at
            || request.requested_projects.is_empty()
        {
            return Err(HandoffError::Forbidden);
        }
        let accepted_projects: BTreeSet<_> = request
            .requested_projects
            .intersection(&request.issuer_effective.project_ids)
            .filter(|project| request.policy_allowed_projects.contains(*project))
            .cloned()
            .collect();
        if accepted_projects.is_empty() {
            return Err(HandoffError::Forbidden);
        }
        let delegated: BTreeSet<_> = request
            .requested_capabilities
            .intersection(&request.issuer_effective.capabilities)
            .filter(|capability| request.policy_allowed_capabilities.contains(*capability))
            .copied()
            .collect();
        let rejected_projects = request
            .requested_projects
            .difference(&accepted_projects)
            .cloned()
            .collect();
        let rejected_capabilities = request
            .requested_capabilities
            .difference(&delegated)
            .copied()
            .collect();
        Ok(HandoffCreationPreview {
            accepted_projects: accepted_projects.into_iter().collect(),
            rejected_projects,
            delegated_capabilities: delegated.into_iter().collect(),
            rejected_capabilities,
            reference_count: reference_count(&request.references)?,
        })
    }

    /// Creates and signs a capsule after exact preview intersection.
    pub fn create(
        &self,
        request: CreateHandoffRequest,
    ) -> Result<(HandoffCapsule, HandoffCreationPreview), HandoffError> {
        let preview = self.preview_creation(&request)?;
        let mut capsule = HandoffCapsule {
            schema_version: SchemaVersion::new("cigar.handoff", 1)
                .map_err(|_error| HandoffError::InvalidInput)?,
            handoff_id: request.handoff_id,
            issuer_id: request.issuer_effective.subject_id,
            recipient: request.recipient,
            task: request.task,
            acceptance_criteria: request.acceptance_criteria,
            project_ids: preview.accepted_projects.clone(),
            delegated_capabilities: preview.delegated_capabilities.clone(),
            rejected_capabilities: preview.rejected_capabilities.clone(),
            budget: request.budget,
            topics: request.topics.into_iter().collect(),
            references: request.references,
            bundle_id: request.bundle_id,
            audience: request.audience,
            created_at: request.created_at,
            expires_at: request.expires_at,
            nonce: request.nonce,
            reusable: request.reusable,
            issuer_key_id: request.issuer_key_ref.as_str().to_owned(),
            signature: Vec::new(),
            extensions: ExtensionMap::default(),
        };
        let payload_digest = capsule_payload_digest(&capsule)?;
        let envelope = self
            .provider
            .sign(SignatureRequest {
                key_ref: &request.issuer_key_ref,
                tenant: &request.issuer_effective.tenant,
                signer: capsule.issuer_id.as_str(),
                purpose: HANDOFF_SIGNATURE_PURPOSE,
                payload_digest,
                signed_at: capsule.created_at.unix_nanos(),
                expires_at: Some(capsule.expires_at.unix_nanos()),
            })
            .map_err(|_error| HandoffError::Unavailable)?;
        capsule.signature = envelope.signature.to_vec();
        capsule
            .validate()
            .map_err(|_error| HandoffError::InvalidInput)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        if state.capsules.contains_key(&capsule.handoff_id)
            || state.revisions.contains_key(&capsule.handoff_id)
        {
            return Err(HandoffError::Replay);
        }
        state.revisions.insert(capsule.handoff_id.clone(), 1);
        state
            .capsules
            .insert(capsule.handoff_id.clone(), capsule.clone());
        state
            .previews
            .insert(capsule.handoff_id.clone(), preview.clone());
        Ok((capsule, preview))
    }

    /// Returns the canonical creation event for atomic context-space publication.
    pub fn creation_event(
        capsule: &HandoffCapsule,
        event_id: RecordId,
    ) -> Result<CoordinationEvent, HandoffError> {
        Ok(CoordinationEvent {
            event_id,
            kind: CoordinationEventKind::HandoffCreated,
            payload_digest: multihash(capsule_payload_digest(capsule)?)?,
        })
    }

    /// Inspects a persisted capsule only for its issuer or resolved recipient.
    pub fn persisted_capsule(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<HandoffCapsule, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::Forbidden)?;
        let visible = capsule_visible(capsule, actor_id, actor_roles);
        visible
            .then(|| capsule.clone())
            .ok_or(HandoffError::Forbidden)
    }

    /// Returns the exact retained creation preview to the issuer or resolved recipient.
    pub fn persisted_preview(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<HandoffCreationPreview, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::Forbidden)?;
        if !capsule_visible(capsule, actor_id, actor_roles) {
            return Err(HandoffError::Forbidden);
        }
        state
            .previews
            .get(handoff_id)
            .cloned()
            .ok_or(HandoffError::Unavailable)
    }

    /// Returns the current optimistic revision to an actor allowed to inspect the capsule.
    pub fn handoff_revision(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<u64, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::Forbidden)?;
        if !capsule_visible(capsule, actor_id, actor_roles) {
            return Err(HandoffError::Forbidden);
        }
        state
            .revisions
            .get(handoff_id)
            .copied()
            .ok_or(HandoffError::Unavailable)
    }

    /// Revokes a capsule exactly once under issuer authority and optimistic revision control.
    pub fn revoke(&self, request: RevokeHandoffRequest) -> Result<HandoffRevocation, HandoffError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(&request.handoff_id)
            .cloned()
            .ok_or(HandoffError::Forbidden)?;
        if capsule.issuer_id != request.actor_id {
            return Err(HandoffError::Forbidden);
        }
        if request.revoked_at < capsule.created_at {
            return Err(HandoffError::InvalidInput);
        }
        if let Some(existing) = state.revocations.get(&request.handoff_id)
            && revocation_matches_request(existing, &request)
        {
            return Ok(existing.clone());
        }
        let revision = state
            .revisions
            .get(&request.handoff_id)
            .copied()
            .ok_or(HandoffError::Unavailable)?;
        if revision != request.expected_revision.0 {
            return Err(HandoffError::RevisionConflict);
        }
        if state.revocations.contains_key(&request.handoff_id) {
            return Err(HandoffError::Revoked);
        }
        if event_id_in_use(&state, &request.event_id) {
            return Err(HandoffError::Replay);
        }
        let next_revision = revision.checked_add(1).ok_or(HandoffError::LimitExceeded)?;
        let event = revocation_event(
            &request.handoff_id,
            &request.actor_id,
            next_revision,
            &request.policy_digest,
            Some(&request.reason_digest),
            request.revoked_at,
            request.event_id,
        )?;
        let revocation = HandoffRevocation {
            handoff_id: request.handoff_id.clone(),
            issuer_id: request.actor_id,
            revision: next_revision,
            policy_digest: request.policy_digest,
            reason_digest: Some(request.reason_digest),
            revoked_at: request.revoked_at,
            event,
        };
        state
            .revisions
            .insert(request.handoff_id.clone(), next_revision);
        state
            .revocations
            .insert(request.handoff_id, revocation.clone());
        Ok(revocation)
    }

    /// Returns an authoritative revocation to an actor allowed to inspect its capsule.
    pub fn persisted_revocation(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
        actor_roles: &BTreeSet<String>,
    ) -> Result<Option<HandoffRevocation>, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::Forbidden)?;
        if !capsule_visible(capsule, actor_id, actor_roles) {
            return Err(HandoffError::Forbidden);
        }
        Ok(state.revocations.get(handoff_id).cloned())
    }

    /// Inspects signature, audience, recipient, time, revocation, scope, and references.
    pub fn inspect_acceptance(
        &self,
        request: &AcceptHandoffRequest,
        authorize_reference: impl Fn(&VersionId) -> bool,
    ) -> Result<AcceptanceInspection, HandoffError> {
        verify_acceptance_request(request)?;
        self.verify_capsule_signature(&request.capsule, &request.tenant, request.now)?;
        {
            let state = self
                .state
                .lock()
                .map_err(|_error| HandoffError::Unavailable)?;
            if state.capsules.get(&request.capsule.handoff_id) != Some(&request.capsule) {
                return Err(HandoffError::Forbidden);
            }
            if state.revocations.contains_key(&request.capsule.handoff_id) {
                return Err(HandoffError::Revoked);
            }
            if state.revisions.get(&request.capsule.handoff_id).copied()
                != Some(request.expected_revision.0)
            {
                return Err(HandoffError::RevisionConflict);
            }
            check_replay_available(&state.replay, request)?;
        }
        if request
            .revoked_key_ids
            .contains(&request.capsule.issuer_key_id)
            || request
                .revoked_principals
                .contains(&request.capsule.issuer_id)
            || request.revoked_principals.contains(&request.recipient_id)
        {
            return Err(HandoffError::Revoked);
        }
        if request.recipient_effective.subject_id != request.recipient_id
            || request.now >= request.recipient_effective.expires_at
        {
            return Err(HandoffError::Forbidden);
        }
        match &request.capsule.recipient {
            RecipientSelector::Principal(principal) if principal != &request.recipient_id => {
                return Err(HandoffError::Forbidden);
            }
            RecipientSelector::Role(role) if !request.recipient_roles.contains(role) => {
                return Err(HandoffError::Forbidden);
            }
            RecipientSelector::Principal(_) | RecipientSelector::Role(_) => {}
        }
        let projects: Vec<_> = request
            .capsule
            .project_ids
            .iter()
            .filter(|project| request.recipient_effective.project_ids.contains(*project))
            .cloned()
            .collect();
        if projects.is_empty() {
            return Err(HandoffError::Forbidden);
        }
        let accepted: BTreeSet<_> = request
            .capsule
            .delegated_capabilities
            .iter()
            .filter(|capability| {
                request
                    .recipient_effective
                    .capabilities
                    .contains(*capability)
                    && request.policy_allowed_capabilities.contains(*capability)
            })
            .copied()
            .collect();
        let rejected_capabilities = request
            .capsule
            .delegated_capabilities
            .iter()
            .filter(|capability| !accepted.contains(*capability))
            .copied()
            .collect();
        let (references, unavailable_references) =
            filter_references(&request.capsule.references, authorize_reference);
        Ok(AcceptanceInspection {
            context: AcceptedHandoffContext {
                recipient_id: request.recipient_id.clone(),
                project_ids: projects,
                capabilities: accepted.into_iter().collect(),
                references,
                budget: request.capsule.budget.clone(),
            },
            rejected_capabilities,
            unavailable_references,
            topics: request.capsule.topics.clone(),
        })
    }

    /// Accepts once, compiles a recipient-specific bundle, persists replay use, and emits a receipt.
    pub fn accept(
        &self,
        request: AcceptHandoffRequest,
        authorize_reference: impl Fn(&VersionId) -> bool,
        compile_recipient_bundle: impl FnOnce(
            &AcceptedHandoffContext,
        ) -> Result<RecipientBundleReceipt, HandoffError>,
    ) -> Result<HandoffAcceptance, HandoffError> {
        let inspection = self.inspect_acceptance(&request, authorize_reference)?;
        let compilation = compile_recipient_bundle(&inspection.context)?;
        if compilation.source_bundle_id != request.capsule.bundle_id
            || compilation.target_plan_revision == 0
        {
            return Err(HandoffError::Forbidden);
        }
        let authority = HandoffAcceptanceAuthority {
            accepted: inspection.context.clone(),
            compilation,
        };
        let acknowledgement_digest = acceptance_digest(&request, &inspection, &authority)?;
        let acceptance = HandoffAcceptance {
            schema_version: SchemaVersion::new("cigar.handoff-acceptance", 1)
                .map_err(|_error| HandoffError::InvalidInput)?,
            acceptance_id: request.acceptance_id.clone(),
            handoff_id: request.capsule.handoff_id.clone(),
            recipient_id: request.recipient_id.clone(),
            accepted_capabilities: inspection.context.capabilities.clone(),
            rejected_capabilities: inspection.rejected_capabilities,
            unavailable_references: inspection.unavailable_references,
            policy_digest: request.policy_digest.clone(),
            bundle_id: authority.compilation.bundle_id.clone(),
            accepted_at: request.accepted_at,
            acknowledgement_digest,
        };
        acceptance
            .validate()
            .and_then(|()| acceptance.validate_against(&request.capsule))
            .map_err(|_error| HandoffError::InvalidInput)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        if state.capsules.get(&request.capsule.handoff_id) != Some(&request.capsule) {
            return Err(HandoffError::Forbidden);
        }
        if state.revocations.contains_key(&request.capsule.handoff_id) {
            return Err(HandoffError::Revoked);
        }
        if state.revisions.get(&request.capsule.handoff_id).copied()
            != Some(request.expected_revision.0)
        {
            return Err(HandoffError::RevisionConflict);
        }
        consume_replay(&mut state.replay, &request)?;
        state
            .acceptances
            .insert(request.acceptance_id.clone(), acceptance.clone());
        state
            .acceptance_authorities
            .insert(request.acceptance_id.clone(), authority);
        state
            .subscriptions
            .insert(request.acceptance_id, inspection.topics);
        Ok(acceptance)
    }

    /// Returns a persisted acceptance only to its authenticated recipient.
    pub fn persisted_acceptance(
        &self,
        acceptance_id: &RecordId,
        recipient_id: &RecordId,
    ) -> Result<HandoffAcceptance, HandoffError> {
        self.state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?
            .acceptances
            .get(acceptance_id)
            .filter(|acceptance| &acceptance.recipient_id == recipient_id)
            .cloned()
            .ok_or(HandoffError::Forbidden)
    }

    /// Resolves the newest durable acceptance matching a recipient, handoff, and result base.
    ///
    /// The public result route does not carry an acceptance identity. Matching all three
    /// authoritative fields prevents a caller from selecting another recipient's receipt, while
    /// the deterministic newest choice supports reusable capsules compiled to the same bundle.
    pub fn acceptance_for_result(
        &self,
        handoff_id: &RecordId,
        recipient_id: &RecordId,
        base_commit_id: &VersionId,
    ) -> Result<HandoffAcceptance, HandoffError> {
        self.state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?
            .acceptances
            .values()
            .filter(|acceptance| {
                &acceptance.handoff_id == handoff_id
                    && &acceptance.recipient_id == recipient_id
                    && &acceptance.bundle_id == base_commit_id
            })
            .max_by(|left, right| {
                left.accepted_at
                    .cmp(&right.accepted_at)
                    .then_with(|| left.acceptance_id.cmp(&right.acceptance_id))
            })
            .cloned()
            .ok_or(HandoffError::Forbidden)
    }

    /// Returns the exact signed topic set for an accepted receipt.
    pub fn subscription_topics(
        &self,
        acceptance_id: &RecordId,
    ) -> Result<Vec<CoordinationTopic>, HandoffError> {
        self.state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?
            .subscriptions
            .get(acceptance_id)
            .cloned()
            .ok_or(HandoffError::Forbidden)
    }

    /// Persists one immutable validated child result under the handoff revision.
    pub fn record_result(
        &self,
        request: RecordHandoffResultRequest,
    ) -> Result<HandoffResultReceipt, HandoffError> {
        request
            .delta
            .validate()
            .map_err(|_error| HandoffError::InvalidInput)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let acceptance = state
            .acceptances
            .get(&request.acceptance_id)
            .cloned()
            .ok_or(HandoffError::Forbidden)?;
        let authority = state
            .acceptance_authorities
            .get(&request.acceptance_id)
            .ok_or(HandoffError::Unavailable)?;
        if acceptance.recipient_id != request.actor_id
            || acceptance.handoff_id != request.delta.handoff_id
            || request.delta.producer_id != request.actor_id
            || request.delta.base_commit_id != acceptance.bundle_id
            || request.current_project_ids.is_empty()
            || !authority
                .accepted
                .project_ids
                .iter()
                .any(|project| request.current_project_ids.contains(project))
        {
            return Err(HandoffError::Forbidden);
        }
        let capsule = state
            .capsules
            .get(&acceptance.handoff_id)
            .ok_or(HandoffError::Unavailable)?;
        acceptance
            .validate_against(capsule)
            .map_err(|_error| HandoffError::InvalidInput)?;

        if let Some(existing) = state.results.get(&request.delta.delta_id) {
            if existing.acceptance_id == request.acceptance_id
                && request.expected_revision.0.checked_add(1) == Some(existing.revision)
                && existing.delta == request.delta
                && existing.event.event_id == request.event_id
            {
                return Ok(existing.clone());
            }
            return Err(HandoffError::Replay);
        }
        if state.revocations.contains_key(&request.delta.handoff_id) {
            return Err(HandoffError::Revoked);
        }
        if event_id_in_use(&state, &request.event_id) {
            return Err(HandoffError::Replay);
        }
        let revision = state
            .revisions
            .get(&request.delta.handoff_id)
            .copied()
            .ok_or(HandoffError::Unavailable)?;
        if revision != request.expected_revision.0 {
            return Err(HandoffError::RevisionConflict);
        }
        let next_revision = revision.checked_add(1).ok_or(HandoffError::LimitExceeded)?;
        let event = result_event(&request.delta, request.event_id)?;
        let delta_id = request.delta.delta_id.clone();
        let handoff_id = request.delta.handoff_id.clone();
        let receipt = HandoffResultReceipt {
            acceptance_id: request.acceptance_id,
            revision: next_revision,
            delta: request.delta,
            event,
        };
        state.revisions.insert(handoff_id, next_revision);
        state.results.insert(delta_id, receipt.clone());
        Ok(receipt)
    }

    /// Returns one persisted child result to its producer or capsule issuer.
    pub fn persisted_result(
        &self,
        delta_id: &RecordId,
        actor_id: &RecordId,
    ) -> Result<HandoffResultReceipt, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let receipt = state.results.get(delta_id).ok_or(HandoffError::Forbidden)?;
        let capsule = state
            .capsules
            .get(&receipt.delta.handoff_id)
            .ok_or(HandoffError::Unavailable)?;
        if &capsule.issuer_id != actor_id && &receipt.delta.producer_id != actor_id {
            return Err(HandoffError::Forbidden);
        }
        Ok(receipt.clone())
    }

    /// Returns all persisted child results visible to the issuer or their exact producer.
    pub fn persisted_results(
        &self,
        handoff_id: &RecordId,
        actor_id: &RecordId,
    ) -> Result<Vec<HandoffResultReceipt>, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::Forbidden)?;
        let issuer = &capsule.issuer_id == actor_id;
        let mut results: Vec<_> = state
            .results
            .values()
            .filter(|receipt| {
                &receipt.delta.handoff_id == handoff_id
                    && (issuer || &receipt.delta.producer_id == actor_id)
            })
            .cloned()
            .collect();
        if !issuer && results.is_empty() {
            return Err(HandoffError::Forbidden);
        }
        results.sort_by_key(|receipt| receipt.revision);
        Ok(results)
    }

    /// Returns complete merge material only to the exact capsule issuer.
    pub fn merge_material(
        &self,
        delta_id: &RecordId,
        issuer_id: &RecordId,
    ) -> Result<HandoffMergeMaterial, HandoffError> {
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        let result = state.results.get(delta_id).ok_or(HandoffError::Forbidden)?;
        let capsule = state
            .capsules
            .get(&result.delta.handoff_id)
            .ok_or(HandoffError::Unavailable)?;
        if &capsule.issuer_id != issuer_id {
            return Err(HandoffError::Forbidden);
        }
        let acceptance = state
            .acceptances
            .get(&result.acceptance_id)
            .ok_or(HandoffError::Unavailable)?;
        let acceptance_authority = state
            .acceptance_authorities
            .get(&result.acceptance_id)
            .ok_or(HandoffError::Unavailable)?;
        Ok(HandoffMergeMaterial {
            capsule: capsule.clone(),
            acceptance: acceptance.clone(),
            acceptance_authority: acceptance_authority.clone(),
            result: result.clone(),
        })
    }

    /// Returns merge material only after re-verifying the signed delegation and current
    /// independent revocation authority.
    pub fn verified_merge_material(
        &self,
        delta_id: &RecordId,
        issuer_id: &RecordId,
        tenant: &str,
        revoked_principals: &BTreeSet<RecordId>,
        revoked_key_ids: &BTreeSet<String>,
    ) -> Result<HandoffMergeMaterial, HandoffError> {
        let material = self.merge_material(delta_id, issuer_id)?;
        if revoked_principals.contains(&material.capsule.issuer_id)
            || revoked_principals.contains(&material.acceptance.recipient_id)
            || revoked_key_ids.contains(&material.capsule.issuer_key_id)
        {
            return Err(HandoffError::Forbidden);
        }
        self.verify_capsule_signature(&material.capsule, tenant, material.acceptance.accepted_at)?;
        let state = self
            .state
            .lock()
            .map_err(|_error| HandoffError::Unavailable)?;
        if state.revocations.contains_key(&material.capsule.handoff_id)
            || material.acceptance.acknowledgement_digest
                != acceptance_authority_digest(
                    &material.acceptance.acceptance_id,
                    &material.acceptance.handoff_id,
                    &material.acceptance.recipient_id,
                    &material.acceptance.accepted_capabilities,
                    &material.acceptance.rejected_capabilities,
                    &material.acceptance.unavailable_references,
                    &material.acceptance.policy_digest,
                    &material.acceptance_authority,
                    &material.acceptance.accepted_at,
                )?
        {
            return Err(HandoffError::Forbidden);
        }
        Ok(material)
    }

    fn verify_capsule_signature(
        &self,
        capsule: &HandoffCapsule,
        tenant: &str,
        now: UtcTimestamp,
    ) -> Result<(), HandoffError> {
        let signature: [u8; 64] = capsule
            .signature
            .as_slice()
            .try_into()
            .map_err(|_error| HandoffError::InvalidSignature)?;
        let key_ref = KeyRef::new(capsule.issuer_key_id.clone())
            .map_err(|_error| HandoffError::InvalidSignature)?;
        let payload_digest = capsule_payload_digest(capsule)?;
        let envelope = SignatureEnvelope {
            algorithm: KeyAlgorithm::Ed25519,
            key_ref,
            signer: capsule.issuer_id.as_str().to_owned(),
            purpose: HANDOFF_SIGNATURE_PURPOSE.to_owned(),
            signed_at: capsule.created_at.unix_nanos(),
            expires_at: Some(capsule.expires_at.unix_nanos()),
            payload_digest,
            signature,
        };
        self.provider
            .verify(
                &envelope,
                SignatureVerification {
                    tenant,
                    signer: capsule.issuer_id.as_str(),
                    purpose: HANDOFF_SIGNATURE_PURPOSE,
                    payload_digest: &payload_digest,
                    now: now.unix_nanos(),
                },
            )
            .map_err(|_error| HandoffError::InvalidSignature)
    }
}

fn check_replay_available(
    replay: &ReplayState,
    request: &AcceptHandoffRequest,
) -> Result<(), HandoffError> {
    if replay.acceptance_ids.contains(&request.acceptance_id)
        || (!request.capsule.reusable
            && replay
                .consumed_one_time_nonces
                .contains(&request.capsule.nonce))
    {
        Err(HandoffError::Replay)
    } else {
        Ok(())
    }
}

fn consume_replay(
    replay: &mut ReplayState,
    request: &AcceptHandoffRequest,
) -> Result<(), HandoffError> {
    if !replay.acceptance_ids.insert(request.acceptance_id.clone()) {
        return Err(HandoffError::Replay);
    }
    if !request.capsule.reusable
        && !replay
            .consumed_one_time_nonces
            .insert(request.capsule.nonce.clone())
    {
        replay.acceptance_ids.remove(&request.acceptance_id);
        return Err(HandoffError::Replay);
    }
    Ok(())
}

fn normalize_legacy_handoff_state(state: &mut HandoffState) {
    if state.revisions.is_empty() && state.revocations.is_empty() && state.results.is_empty() {
        for handoff_id in state.capsules.keys() {
            state.revisions.insert(handoff_id.clone(), 1);
        }
    }
    if state.previews.is_empty() {
        for (handoff_id, capsule) in &state.capsules {
            let preview = HandoffCreationPreview {
                accepted_projects: capsule.project_ids.clone(),
                rejected_projects: Vec::new(),
                delegated_capabilities: capsule.delegated_capabilities.clone(),
                rejected_capabilities: capsule.rejected_capabilities.clone(),
                reference_count: reference_count(&capsule.references).unwrap_or(0),
            };
            state.previews.insert(handoff_id.clone(), preview);
        }
    }
}

fn capsule_visible(
    capsule: &HandoffCapsule,
    actor_id: &RecordId,
    actor_roles: &BTreeSet<String>,
) -> bool {
    &capsule.issuer_id == actor_id
        || match &capsule.recipient {
            RecipientSelector::Principal(recipient) => recipient == actor_id,
            RecipientSelector::Role(role) => actor_roles.contains(role),
        }
}

fn revocation_matches_request(
    revocation: &HandoffRevocation,
    request: &RevokeHandoffRequest,
) -> bool {
    revocation.handoff_id == request.handoff_id
        && revocation.issuer_id == request.actor_id
        && request.expected_revision.0.checked_add(1) == Some(revocation.revision)
        && revocation.policy_digest == request.policy_digest
        && revocation.reason_digest.as_ref() == Some(&request.reason_digest)
        && revocation.revoked_at == request.revoked_at
        && revocation.event.event_id == request.event_id
}

fn event_id_in_use(state: &HandoffState, event_id: &RecordId) -> bool {
    state
        .revocations
        .values()
        .any(|revocation| &revocation.event.event_id == event_id)
        || state
            .results
            .values()
            .any(|result| &result.event.event_id == event_id)
}

fn revocation_event(
    handoff_id: &RecordId,
    issuer_id: &RecordId,
    revision: u64,
    policy_digest: &ContentDigest,
    reason_digest: Option<&ContentDigest>,
    revoked_at: UtcTimestamp,
    event_id: RecordId,
) -> Result<CoordinationEvent, HandoffError> {
    let payload_digest = if let Some(reason_digest) = reason_digest {
        let payload = (
            handoff_id,
            issuer_id,
            revision,
            policy_digest,
            reason_digest,
            revoked_at,
        );
        domain_digest(b"CIGAR-HANDOFF-REVOCATION\0v2\0", &payload)?
    } else {
        let legacy_payload = (handoff_id, issuer_id, revision, policy_digest, revoked_at);
        domain_digest(b"CIGAR-HANDOFF-REVOCATION\0v1\0", &legacy_payload)?
    };
    Ok(CoordinationEvent {
        event_id,
        kind: CoordinationEventKind::HandoffRevoked,
        payload_digest: multihash(payload_digest)?,
    })
}

fn result_event(
    delta: &HandoffDelta,
    event_id: RecordId,
) -> Result<CoordinationEvent, HandoffError> {
    Ok(CoordinationEvent {
        event_id,
        kind: CoordinationEventKind::AgentResultProposed,
        payload_digest: multihash(domain_digest(b"CIGAR-HANDOFF-RESULT\0v1\0", delta)?)?,
    })
}

fn validate_handoff_state(state: &HandoffState) -> Result<(), HandoffError> {
    if state.revisions.keys().ne(state.capsules.keys())
        || state.previews.keys().ne(state.capsules.keys())
    {
        return Err(HandoffError::InvalidInput);
    }
    for (handoff_id, capsule) in &state.capsules {
        capsule
            .validate()
            .map_err(|_error| HandoffError::InvalidInput)?;
        let preview = state
            .previews
            .get(handoff_id)
            .ok_or(HandoffError::InvalidInput)?;
        if &capsule.handoff_id != handoff_id
            || state.revisions.get(handoff_id).copied().unwrap_or(0) == 0
            || preview.accepted_projects != capsule.project_ids
            || preview.delegated_capabilities != capsule.delegated_capabilities
            || preview.rejected_capabilities != capsule.rejected_capabilities
            || preview.reference_count != reference_count(&capsule.references)?
            || !strictly_sorted(&preview.accepted_projects)
            || !strictly_sorted(&preview.rejected_projects)
            || preview
                .rejected_projects
                .iter()
                .any(|project| preview.accepted_projects.binary_search(project).is_ok())
        {
            return Err(HandoffError::InvalidInput);
        }
    }

    let acceptance_ids: BTreeSet<_> = state.acceptances.keys().cloned().collect();
    if state.replay.acceptance_ids != acceptance_ids
        || state
            .acceptance_authorities
            .keys()
            .ne(state.acceptances.keys())
        || state.subscriptions.keys().ne(state.acceptances.keys())
    {
        return Err(HandoffError::InvalidInput);
    }
    let mut expected_nonces = BTreeSet::new();
    for (acceptance_id, acceptance) in &state.acceptances {
        acceptance
            .validate()
            .map_err(|_error| HandoffError::InvalidInput)?;
        let capsule = state
            .capsules
            .get(&acceptance.handoff_id)
            .ok_or(HandoffError::InvalidInput)?;
        let authority = state
            .acceptance_authorities
            .get(acceptance_id)
            .ok_or(HandoffError::InvalidInput)?;
        acceptance
            .validate_against(capsule)
            .map_err(|_error| HandoffError::InvalidInput)?;
        if &acceptance.acceptance_id != acceptance_id
            || state.subscriptions.get(acceptance_id) != Some(&capsule.topics)
            || authority.accepted.recipient_id != acceptance.recipient_id
            || authority.accepted.project_ids.is_empty()
            || !strictly_sorted(&authority.accepted.project_ids)
            || authority
                .accepted
                .project_ids
                .iter()
                .any(|project| capsule.project_ids.binary_search(project).is_err())
            || authority.accepted.capabilities != acceptance.accepted_capabilities
            || authority.accepted.budget != capsule.budget
            || !references_are_attenuated(
                &authority.accepted.references,
                &capsule.references,
                &acceptance.unavailable_references,
            )
            || authority.compilation.bundle_id != acceptance.bundle_id
            || authority.compilation.source_bundle_id != capsule.bundle_id
            || authority.compilation.target_plan_revision == 0
            || acceptance.acknowledgement_digest
                != acceptance_authority_digest(
                    &acceptance.acceptance_id,
                    &acceptance.handoff_id,
                    &acceptance.recipient_id,
                    &acceptance.accepted_capabilities,
                    &acceptance.rejected_capabilities,
                    &acceptance.unavailable_references,
                    &acceptance.policy_digest,
                    authority,
                    &acceptance.accepted_at,
                )?
        {
            return Err(HandoffError::InvalidInput);
        }
        if !capsule.reusable && !expected_nonces.insert(capsule.nonce.clone()) {
            return Err(HandoffError::InvalidInput);
        }
    }
    if state.replay.consumed_one_time_nonces != expected_nonces {
        return Err(HandoffError::InvalidInput);
    }

    let mut mutation_revisions: BTreeMap<RecordId, BTreeSet<u64>> = state
        .capsules
        .keys()
        .cloned()
        .map(|handoff_id| (handoff_id, BTreeSet::new()))
        .collect();
    let mut event_ids = BTreeSet::new();
    for (handoff_id, revocation) in &state.revocations {
        let capsule = state
            .capsules
            .get(handoff_id)
            .ok_or(HandoffError::InvalidInput)?;
        let expected_event = revocation_event(
            handoff_id,
            &revocation.issuer_id,
            revocation.revision,
            &revocation.policy_digest,
            revocation.reason_digest.as_ref(),
            revocation.revoked_at,
            revocation.event.event_id.clone(),
        )?;
        if &revocation.handoff_id != handoff_id
            || revocation.issuer_id != capsule.issuer_id
            || revocation.revoked_at < capsule.created_at
            || revocation.event != expected_event
            || !event_ids.insert(revocation.event.event_id.clone())
            || !mutation_revisions
                .get_mut(handoff_id)
                .ok_or(HandoffError::InvalidInput)?
                .insert(revocation.revision)
        {
            return Err(HandoffError::InvalidInput);
        }
    }
    for (delta_id, result) in &state.results {
        result
            .delta
            .validate()
            .map_err(|_error| HandoffError::InvalidInput)?;
        let acceptance = state
            .acceptances
            .get(&result.acceptance_id)
            .ok_or(HandoffError::InvalidInput)?;
        let expected_event = result_event(&result.delta, result.event.event_id.clone())?;
        if &result.delta.delta_id != delta_id
            || result.delta.handoff_id != acceptance.handoff_id
            || result.delta.producer_id != acceptance.recipient_id
            || result.delta.base_commit_id != acceptance.bundle_id
            || result.event != expected_event
            || state
                .revocations
                .get(&result.delta.handoff_id)
                .is_some_and(|revocation| result.revision >= revocation.revision)
            || !event_ids.insert(result.event.event_id.clone())
            || !mutation_revisions
                .get_mut(&result.delta.handoff_id)
                .ok_or(HandoffError::InvalidInput)?
                .insert(result.revision)
        {
            return Err(HandoffError::InvalidInput);
        }
    }
    for (handoff_id, current_revision) in &state.revisions {
        let revisions = mutation_revisions
            .get(handoff_id)
            .ok_or(HandoffError::InvalidInput)?;
        let mutation_count =
            u64::try_from(revisions.len()).map_err(|_error| HandoffError::LimitExceeded)?;
        let expected_current = mutation_count
            .checked_add(1)
            .ok_or(HandoffError::LimitExceeded)?;
        if *current_revision != expected_current
            || revisions.iter().copied().ne(2..=expected_current)
        {
            return Err(HandoffError::InvalidInput);
        }
    }
    Ok(())
}

/// Semantic mapping for one child result record entering a parent overlay.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResultMergeKind {
    /// Durable decision atom.
    Decision,
    /// Durable artifact atom.
    Artifact,
    /// Exact source-code change atom.
    SourceChange,
}

/// Semantic mapping for one child result record entering a parent overlay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultMergeMapping {
    /// Child record version.
    pub version_id: VersionId,
    /// Server-resolved semantic kind; callers cannot assign this from an opaque identifier.
    pub kind: ResultMergeKind,
    /// Parent semantic resource key.
    pub resource_key: ResourceKey,
}

/// Auditable result-merge receipt; follow-up capabilities remain requests only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultMergeReceipt {
    /// Child delta identity.
    pub delta_id: RecordId,
    /// Versions proposed into the parent overlay.
    pub proposed_versions: Vec<VersionId>,
    /// References rejected by current parent authorization.
    pub rejected_versions: Vec<VersionId>,
    /// Follow-up capabilities explicitly left ungranted.
    pub ungranted_followup_capabilities: Vec<Capability>,
}

/// Validates and proposes a child result into a private parent overlay for ordinary merge handling.
#[allow(clippy::too_many_arguments)]
pub fn merge_child_result(
    service: &ContextSpaceService,
    space_id: &ContextSpaceId,
    overlay_id: &RecordId,
    parent_id: &RecordId,
    capsule: &HandoffCapsule,
    acceptance: &HandoffAcceptance,
    delta: &HandoffDelta,
    expected_base_commit_id: &VersionId,
    mappings: &[ResultMergeMapping],
    currently_authorized: impl Fn(&VersionId) -> bool,
) -> Result<ResultMergeReceipt, HandoffError> {
    delta
        .validate()
        .map_err(|_error| HandoffError::InvalidInput)?;
    if delta.handoff_id != capsule.handoff_id
        || acceptance.handoff_id != capsule.handoff_id
        || delta.producer_id != acceptance.recipient_id
        || &delta.base_commit_id != expected_base_commit_id
    {
        return Err(HandoffError::Forbidden);
    }
    if delta
        .claims
        .iter()
        .flat_map(|claim| &claim.evidence)
        .any(|version| !currently_authorized(version))
    {
        return Err(HandoffError::Forbidden);
    }
    let mut expected_kinds = BTreeMap::new();
    for (versions, kind) in [
        (&delta.decisions, ResultMergeKind::Decision),
        (&delta.artifacts, ResultMergeKind::Artifact),
        (&delta.source_changes, ResultMergeKind::SourceChange),
    ] {
        for version in versions {
            if expected_kinds.insert(version, kind).is_some() {
                return Err(HandoffError::InvalidInput);
            }
        }
    }
    let mapping_by_version: BTreeMap<_, _> = mappings
        .iter()
        .map(|mapping| (&mapping.version_id, mapping))
        .collect();
    if mapping_by_version.len() != mappings.len()
        || mapping_by_version.len() != expected_kinds.len()
        || expected_kinds.iter().any(|(version, kind)| {
            mapping_by_version
                .get(version)
                .is_none_or(|mapping| mapping.kind != *kind)
        })
    {
        return Err(HandoffError::InvalidInput);
    }
    let mut proposed_versions = Vec::new();
    let mut rejected_versions = Vec::new();
    for (versions, kind, constructor) in [
        (
            &delta.decisions,
            ResultMergeKind::Decision,
            OverlayMutation::Decision as fn(VersionId) -> OverlayMutation,
        ),
        (
            &delta.artifacts,
            ResultMergeKind::Artifact,
            OverlayMutation::Artifact as fn(VersionId) -> OverlayMutation,
        ),
        (
            &delta.source_changes,
            ResultMergeKind::SourceChange,
            OverlayMutation::Atom as fn(VersionId) -> OverlayMutation,
        ),
    ] {
        for version in versions {
            if !currently_authorized(version) {
                rejected_versions.push(version.clone());
                continue;
            }
            let mapping = mapping_by_version
                .get(version)
                .ok_or(HandoffError::InvalidInput)?;
            if mapping.kind != kind {
                return Err(HandoffError::InvalidInput);
            }
            service
                .propose(
                    space_id,
                    overlay_id,
                    parent_id,
                    ProposedMutation {
                        key: mapping.resource_key.clone(),
                        mutation: constructor(version.clone()),
                    },
                )
                .map_err(map_space_error)?;
            proposed_versions.push(version.clone());
        }
    }
    proposed_versions.sort();
    proposed_versions.dedup();
    rejected_versions.sort();
    rejected_versions.dedup();
    Ok(ResultMergeReceipt {
        delta_id: delta.delta_id.clone(),
        proposed_versions,
        rejected_versions,
        ungranted_followup_capabilities: delta.requested_followup_capabilities.clone(),
    })
}

/// Reference-handoff efficiency result used by the packet outcome gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffEfficiency {
    /// Parent transcript baseline tokens.
    pub parent_transcript_tokens: u32,
    /// Typed reference handoff and first-bundle tokens.
    pub handoff_tokens: u32,
}

impl HandoffEfficiency {
    /// Returns whether reference handoff stays at or below 20% of transcript baseline.
    #[must_use]
    pub fn within_twenty_percent(self) -> bool {
        self.parent_transcript_tokens > 0
            && u64::from(self.handoff_tokens).saturating_mul(100)
                <= u64::from(self.parent_transcript_tokens).saturating_mul(20)
    }
}

fn verify_acceptance_request(request: &AcceptHandoffRequest) -> Result<(), HandoffError> {
    request
        .capsule
        .validate()
        .map_err(|_error| HandoffError::InvalidInput)?;
    if request.expected_audience != request.capsule.audience || !request.target_allowed {
        return Err(HandoffError::Forbidden);
    }
    if request.now < request.capsule.created_at
        || request.now >= request.capsule.expires_at
        || request.accepted_at != request.now
    {
        return Err(HandoffError::Expired);
    }
    Ok(())
}

fn filter_references(
    references: &HandoffReferences,
    authorize: impl Fn(&VersionId) -> bool,
) -> (HandoffReferences, Vec<VersionId>) {
    let mut unavailable = Vec::new();
    let mut filter = |values: &[VersionId]| {
        values
            .iter()
            .filter_map(|version| {
                if authorize(version) {
                    Some(version.clone())
                } else {
                    unavailable.push(version.clone());
                    None
                }
            })
            .collect()
    };
    let filtered = HandoffReferences {
        sources: filter(&references.sources),
        states: filter(&references.states),
        decisions: filter(&references.decisions),
        artifacts: filter(&references.artifacts),
        uncertainties: filter(&references.uncertainties),
        effects: filter(&references.effects),
    };
    unavailable.sort();
    unavailable.dedup();
    (filtered, unavailable)
}

fn references_are_attenuated(
    accepted: &HandoffReferences,
    capsule: &HandoffReferences,
    unavailable: &[VersionId],
) -> bool {
    let accepted_categories = [
        &accepted.sources,
        &accepted.states,
        &accepted.decisions,
        &accepted.artifacts,
        &accepted.uncertainties,
        &accepted.effects,
    ];
    let capsule_categories = [
        &capsule.sources,
        &capsule.states,
        &capsule.decisions,
        &capsule.artifacts,
        &capsule.uncertainties,
        &capsule.effects,
    ];
    if accepted_categories
        .iter()
        .zip(capsule_categories.iter())
        .any(|(accepted_values, capsule_values)| {
            !strictly_sorted(accepted_values)
                || accepted_values
                    .iter()
                    .any(|value| capsule_values.binary_search(value).is_err())
        })
    {
        return false;
    }
    let accepted_set: BTreeSet<_> = accepted_categories
        .iter()
        .flat_map(|values| values.iter().cloned())
        .collect();
    let capsule_set: BTreeSet<_> = capsule_categories
        .iter()
        .flat_map(|values| values.iter().cloned())
        .collect();
    let expected_unavailable: Vec<_> = capsule_set.difference(&accepted_set).cloned().collect();
    expected_unavailable == unavailable
}

fn reference_count(references: &HandoffReferences) -> Result<usize, HandoffError> {
    [
        references.sources.len(),
        references.states.len(),
        references.decisions.len(),
        references.artifacts.len(),
        references.uncertainties.len(),
        references.effects.len(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, count| total.checked_add(count))
    .ok_or(HandoffError::LimitExceeded)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| matches!((window.first(), window.get(1)), (Some(left), Some(right)) if left < right))
}

fn capsule_payload_digest(capsule: &HandoffCapsule) -> Result<[u8; 32], HandoffError> {
    let mut unsigned = capsule.clone();
    unsigned.signature.clear();
    domain_digest(b"CIGAR-HANDOFF\0v1\0", &unsigned)
}

fn acceptance_digest(
    request: &AcceptHandoffRequest,
    inspection: &AcceptanceInspection,
    authority: &HandoffAcceptanceAuthority,
) -> Result<ContentDigest, HandoffError> {
    acceptance_authority_digest(
        &request.acceptance_id,
        &request.capsule.handoff_id,
        &request.recipient_id,
        &inspection.context.capabilities,
        &inspection.rejected_capabilities,
        &inspection.unavailable_references,
        &request.policy_digest,
        authority,
        &request.accepted_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn acceptance_authority_digest(
    acceptance_id: &RecordId,
    handoff_id: &RecordId,
    recipient_id: &RecordId,
    accepted_capabilities: &[Capability],
    rejected_capabilities: &[Capability],
    unavailable_references: &[VersionId],
    policy_digest: &ContentDigest,
    authority: &HandoffAcceptanceAuthority,
    accepted_at: &UtcTimestamp,
) -> Result<ContentDigest, HandoffError> {
    let value = (
        acceptance_id,
        handoff_id,
        recipient_id,
        accepted_capabilities,
        rejected_capabilities,
        unavailable_references,
        policy_digest,
        authority,
        accepted_at,
    );
    let digest = domain_digest(b"CIGAR-HANDOFF-ACCEPTANCE\0v1\0", &value)?;
    multihash(digest)
}

fn multihash(digest: [u8; 32]) -> Result<ContentDigest, HandoffError> {
    let mut encoded = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| HandoffError::Unavailable)?;
    }
    ContentDigest::new(encoded).map_err(|_error| HandoffError::Unavailable)
}

fn domain_digest(domain: &[u8], value: &impl serde::Serialize) -> Result<[u8; 32], HandoffError> {
    let json = serde_json::to_vec(value).map_err(|_error| HandoffError::InvalidInput)?;
    let node = parse_strict_json(&json).map_err(|_error| HandoffError::InvalidInput)?;
    let cbor = to_deterministic_cbor(&node).map_err(|_error| HandoffError::InvalidInput)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(cbor);
    Ok(hasher.finalize().into())
}

fn map_space_error(error: SpaceError) -> HandoffError {
    match error {
        SpaceError::InvalidInput => HandoffError::InvalidInput,
        SpaceError::NotFound | SpaceError::Forbidden => HandoffError::Forbidden,
        SpaceError::StaleRevision | SpaceError::Conflict => HandoffError::Merge,
        SpaceError::LimitExceeded => HandoffError::LimitExceeded,
        SpaceError::Integrity => HandoffError::Unavailable,
    }
}
