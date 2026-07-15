//! Compiled declarative rule DAG, immutable snapshots, cache, and hard-gate engine.

use crate::{
    DisclosureClass, PolicyDecision, PolicyError, PolicyErrorCode, PolicyInvalidationEvent,
    PolicyInvalidationReason, PolicyOutcome, PolicyProfile, PolicyReason, PolicyRequest,
    PolicyResource, PolicyRule, PolicySnapshot, TimingClass,
};
use cigar_canon::{parse_strict_json, to_deterministic_cbor};
use cigar_protocol::{
    Capability, Classification, ContentDigest, InstructionAuthority, Lifecycle, RecordId,
    RiskLevel, UtcTimestamp,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    Arc, RwLock, Weak,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// Maximum number of policy decisions retained by one engine process.
pub const MAX_POLICY_CACHE_ENTRIES: usize = 4_096;

/// Maximum number of policy decisions retained for one tenant.
pub const MAX_POLICY_CACHE_ENTRIES_PER_TENANT: usize = 512;

/// Maximum process-local lifetime of a retrieval proof even when upstream grants live longer.
pub const MAX_RETRIEVAL_AUTHORIZATION_TTL: Duration = Duration::from_secs(300);

/// Content-free policy decision-cache measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyCacheStatistics {
    /// Current process-wide cache cardinality.
    pub entries: usize,
    /// Largest current cardinality attributed to any one tenant.
    pub maximum_tenant_entries: usize,
    /// Successful lookups since engine creation.
    pub hits: u64,
    /// Evaluated misses since engine creation.
    pub misses: u64,
    /// Entries removed to enforce hard capacity limits.
    pub capacity_evictions: u64,
    /// Entries removed after their exclusive expiry.
    pub expired_evictions: u64,
}

/// Immutable retrieval claims released only by a current policy-issued authorization.
///
/// The claims contain no protected content. Callers must obtain them through
/// [`RetrievalAuthorization::revalidate`], which checks the issuing engine's current policy,
/// availability, revocation epoch, principal, grants, resources, and monotonic expiry.
#[derive(Clone, Eq, PartialEq)]
pub struct RetrievalAuthorizationClaims {
    principal_id: RecordId,
    tenant_id: RecordId,
    project_ids: BTreeSet<RecordId>,
    purpose: String,
    processor: String,
    maximum_classification: cigar_protocol::Classification,
    maximum_instruction_authority: cigar_protocol::InstructionAuthority,
    valid_at: UtcTimestamp,
    observed_as_of: UtcTimestamp,
    vector_allowed: bool,
    policy_digest: ContentDigest,
    policy_revision: u64,
    revocation_epoch: u64,
    partition_digest: ContentDigest,
}

/// Canonical per-record metadata evaluated before a record may enter retrieval scoring.
#[derive(Clone, Eq, PartialEq)]
pub struct RetrievalResourceAuthorizationRequest {
    /// Exact normalized resource digest subject to current resource revocation.
    pub input_digest: ContentDigest,
    /// Canonical owning tenant from the indexed record.
    pub tenant_id: RecordId,
    /// Canonical project scope from the indexed record.
    pub project_ids: BTreeSet<RecordId>,
    /// Canonical allowed purposes from the indexed record.
    pub allowed_purposes: BTreeSet<String>,
    /// Canonical processor constraints; empty means no additional record-level restriction.
    pub allowed_processors: BTreeSet<String>,
    /// Canonical information classification.
    pub classification: Classification,
    /// Canonical lifecycle.
    pub lifecycle: Lifecycle,
    /// Whether canonical record integrity was verified.
    pub integrity_verified: bool,
    /// Inclusive canonical world-valid start.
    pub valid_from: UtcTimestamp,
    /// Exclusive canonical world-valid end.
    pub valid_until: Option<UtcTimestamp>,
    /// Canonical transaction observation time.
    pub observed_at: UtcTimestamp,
    /// Canonical instruction authority.
    pub instruction_authority: InstructionAuthority,
}

impl fmt::Debug for RetrievalResourceAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalResourceAuthorizationRequest")
            .field("project_count", &self.project_ids.len())
            .field("allowed_purpose_count", &self.allowed_purposes.len())
            .field("allowed_processor_count", &self.allowed_processors.len())
            .field("classification", &self.classification)
            .field("lifecycle", &self.lifecycle)
            .field("integrity_verified", &self.integrity_verified)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("observed_at", &self.observed_at)
            .field("instruction_authority", &self.instruction_authority)
            .finish_non_exhaustive()
    }
}

impl RetrievalAuthorizationClaims {
    /// Authenticated principal bound to this authorization.
    #[must_use]
    pub const fn principal_id(&self) -> &RecordId {
        &self.principal_id
    }

    /// Exact owning tenant bound to this authorization.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Non-empty exact project scope authorized by current policy.
    #[must_use]
    pub const fn project_ids(&self) -> &BTreeSet<RecordId> {
        &self.project_ids
    }

    /// Exact authorized use purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Exact authorized processor.
    #[must_use]
    pub fn processor(&self) -> &str {
        &self.processor
    }

    /// Greatest caller-visible information classification.
    #[must_use]
    pub const fn maximum_classification(&self) -> cigar_protocol::Classification {
        self.maximum_classification
    }

    /// Greatest caller-visible instruction authority.
    #[must_use]
    pub const fn maximum_instruction_authority(&self) -> cigar_protocol::InstructionAuthority {
        self.maximum_instruction_authority
    }

    /// World-valid instant frozen by the policy request.
    #[must_use]
    pub const fn valid_at(&self) -> UtcTimestamp {
        self.valid_at
    }

    /// Transaction-time observation bound frozen by the policy request.
    #[must_use]
    pub const fn observed_as_of(&self) -> UtcTimestamp {
        self.observed_as_of
    }

    /// Whether the exact processor gate permits the optional vector channel.
    #[must_use]
    pub const fn vector_allowed(&self) -> bool {
        self.vector_allowed
    }

    /// Immutable installed policy digest used for this authorization.
    #[must_use]
    pub const fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    /// Immutable installed policy revision used for this authorization.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Exact current revocation epoch used for this authorization.
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Digest of every retrieval authorization and partition semantic.
    #[must_use]
    pub const fn partition_digest(&self) -> &ContentDigest {
        &self.partition_digest
    }
}

impl fmt::Debug for RetrievalAuthorizationClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalAuthorizationClaims")
            .field("project_count", &self.project_ids.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("processor_bytes", &self.processor.len())
            .field("maximum_classification", &self.maximum_classification)
            .field(
                "maximum_instruction_authority",
                &self.maximum_instruction_authority,
            )
            .field("valid_at", &self.valid_at)
            .field("observed_as_of", &self.observed_as_of)
            .field("vector_allowed", &self.vector_allowed)
            .field("policy_revision", &self.policy_revision)
            .field("revocation_epoch", &self.revocation_epoch)
            .finish_non_exhaustive()
    }
}

/// Opaque process-local proof that current policy authorized one retrieval partition.
///
/// This type cannot be constructed or deserialized outside the policy engine. Cloning preserves
/// the same issuing engine, snapshot, revocation epoch, and monotonic lifetime; it cannot add
/// projects, change purpose or processor, increase classification, or enable vectors.
#[derive(Clone)]
pub struct RetrievalAuthorization {
    authority: Weak<CompiledPolicyEngine>,
    claims: RetrievalAuthorizationClaims,
    grant_ids: BTreeSet<RecordId>,
    resource_digests: BTreeSet<ContentDigest>,
    request_template: PolicyRequest,
    monotonic_expires_at: Instant,
}

impl RetrievalAuthorization {
    /// Rechecks the issuing engine's current state before protected retrieval work or disclosure.
    pub fn revalidate(&self) -> Result<RetrievalAuthorizationClaims, PolicyError> {
        if Instant::now() >= self.monotonic_expires_at {
            return Err(PolicyError::new(PolicyErrorCode::Revoked));
        }
        let authority = self
            .authority
            .upgrade()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let state = authority
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !state.available {
            return Err(PolicyError::new(PolicyErrorCode::Unavailable));
        }
        if !snapshot.descriptor.protected
            || snapshot.descriptor.revision != self.claims.policy_revision
            || snapshot.descriptor.policy_digest != self.claims.policy_digest
            || state.revocation_epoch != self.claims.revocation_epoch
            || state.revoked_principals.contains(&self.claims.principal_id)
            || !self.grant_ids.is_disjoint(&state.revoked_grants)
            || !self.resource_digests.is_disjoint(&state.revoked_resources)
        {
            return Err(PolicyError::new(PolicyErrorCode::Revoked));
        }
        Ok(self.claims.clone())
    }

    /// Evaluates one canonical record through current metadata policy before scoring.
    ///
    /// A determinate denial returns `Ok(false)` so it is indistinguishable from absence. Policy
    /// outage, snapshot change, revocation after proof issuance, and proof expiry fail the complete
    /// query closed.
    pub fn authorize_resource(
        &self,
        resource: &RetrievalResourceAuthorizationRequest,
        processor_required: bool,
    ) -> Result<bool, PolicyError> {
        self.revalidate()?;
        if resource.project_ids.is_empty()
            || resource.project_ids.len() > crate::MAX_POLICY_SELECTORS
            || resource.allowed_purposes.is_empty()
            || resource.allowed_purposes.len() > crate::MAX_POLICY_SELECTORS
            || resource.allowed_processors.len() > crate::MAX_POLICY_SELECTORS
        {
            return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
        }
        let projects: BTreeSet<_> = resource
            .project_ids
            .intersection(&self.claims.project_ids)
            .cloned()
            .collect();
        if projects.is_empty() || resource.tenant_id != self.claims.tenant_id {
            return Ok(false);
        }
        let authority = self
            .authority
            .upgrade()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let state = authority
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !state.available
            || !snapshot.descriptor.protected
            || snapshot.descriptor.revision != self.claims.policy_revision
            || snapshot.descriptor.policy_digest != self.claims.policy_digest
            || state.revocation_epoch != self.claims.revocation_epoch
        {
            return Err(PolicyError::new(PolicyErrorCode::Revoked));
        }
        for project_id in projects {
            let mut request = self.request_template.clone();
            request.input_digest = resource.input_digest.clone();
            request.tenant_id = resource.tenant_id.clone();
            request.project_id = Some(project_id);
            request
                .allowed_purposes
                .clone_from(&resource.allowed_purposes);
            request.allowed_processors = if resource.allowed_processors.is_empty() {
                BTreeSet::from(["*".to_owned()])
            } else {
                resource.allowed_processors.clone()
            };
            request.classification = resource.classification;
            request.lifecycle = resource.lifecycle;
            request.integrity_verified = resource.integrity_verified;
            request.valid_from = resource.valid_from;
            request.valid_until = resource.valid_until;
            request.observed_at = resource.observed_at;
            request.instruction_authority = resource.instruction_authority;
            let mut allowed = true;
            let mut resources = vec![PolicyResource::Metadata, PolicyResource::Content];
            if processor_required {
                resources.push(PolicyResource::Processor);
            }
            for policy_resource in resources {
                request.resource = policy_resource;
                validate_request(policy_resource, &request)?;
                let decision = evaluate(
                    snapshot,
                    &request,
                    &state.revoked_principals,
                    &state.revoked_grants,
                    &state.revoked_resources,
                )?;
                if decision.outcome != PolicyOutcome::Allow {
                    allowed = false;
                    break;
                }
            }
            if allowed {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl PartialEq for RetrievalAuthorization {
    fn eq(&self, other: &Self) -> bool {
        self.authority.ptr_eq(&other.authority)
            && self.claims == other.claims
            && self.grant_ids == other.grant_ids
            && self.resource_digests == other.resource_digests
            && self.request_template == other.request_template
            && self.monotonic_expires_at == other.monotonic_expires_at
    }
}

impl Eq for RetrievalAuthorization {}

impl fmt::Debug for RetrievalAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetrievalAuthorization")
            .field("claims", &self.claims)
            .field("grant_count", &self.grant_ids.len())
            .field("resource_count", &self.resource_digests.len())
            .finish_non_exhaustive()
    }
}

/// Non-bypassable policy entry points for every protected resource boundary.
pub trait PolicyEngine: Send + Sync {
    /// Returns the current immutable snapshot or fails closed.
    fn snapshot(&self) -> Result<PolicySnapshot, PolicyError>;
    /// Authorizes retrieval partition construction.
    fn authorize_partition(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Authorizes metadata eligibility.
    fn authorize_metadata(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Authorizes protected content loading.
    fn authorize_content(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Authorizes processor plaintext delivery.
    fn authorize_processor(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Reauthorizes an existing bundle under current policy and revocation state.
    fn authorize_bundle(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Reauthorizes handoff creation or acceptance.
    fn authorize_handoff(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
    /// Authorizes an external effect operation.
    fn authorize_effect(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError>;
}

#[derive(Clone)]
struct CompiledSnapshot {
    descriptor: PolicySnapshot,
    rules: Vec<PolicyRule>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CacheKey {
    tenant_id: RecordId,
    request_digest: ContentDigest,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
}

struct EngineState {
    available: bool,
    snapshot: Option<CompiledSnapshot>,
    revoked_principals: BTreeSet<RecordId>,
    revoked_grants: BTreeSet<RecordId>,
    revoked_resources: BTreeSet<ContentDigest>,
    revocation_epoch: u64,
    invalidations: Vec<PolicyInvalidationEvent>,
    cache: BTreeMap<CacheKey, PolicyDecision>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            available: true,
            snapshot: None,
            revoked_principals: BTreeSet::new(),
            revoked_grants: BTreeSet::new(),
            revoked_resources: BTreeSet::new(),
            revocation_epoch: 0,
            invalidations: Vec::new(),
            cache: BTreeMap::new(),
        }
    }
}

/// Thread-safe immutable-snapshot policy engine.
#[derive(Default)]
pub struct CompiledPolicyEngine {
    state: RwLock<EngineState>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    cache_capacity_evictions: AtomicU64,
    cache_expired_evictions: AtomicU64,
}

impl fmt::Debug for CompiledPolicyEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledPolicyEngine")
    }
}

impl CompiledPolicyEngine {
    /// Atomically authorizes and seals one non-empty multi-project retrieval partition.
    ///
    /// Every project is evaluated through both the partition and processor hard gates under one
    /// immutable protected policy snapshot. The returned proof is process-local and is rejected as
    /// soon as policy, revocation, availability, or its monotonic decision lifetime changes.
    pub fn authorize_retrieval_partition(
        self: &Arc<Self>,
        requests: &[PolicyRequest],
    ) -> Result<RetrievalAuthorization, PolicyError> {
        let first = requests
            .first()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
        if requests.len() > crate::MAX_POLICY_SELECTORS {
            return Err(PolicyError::new(PolicyErrorCode::LimitExceeded));
        }
        if first.processor.is_none() {
            return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
        }
        let mut project_ids = BTreeSet::new();
        let mut normalized_first = first.clone();
        normalized_first.project_id = None;
        for request in requests {
            validate_request(PolicyResource::Partition, request)?;
            let project_id = request
                .project_id
                .clone()
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
            if !project_ids.insert(project_id) {
                return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
            }
            let mut normalized = request.clone();
            normalized.project_id = None;
            if normalized != normalized_first {
                return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
            }
        }

        let state = self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !state.available {
            return Err(PolicyError::new(PolicyErrorCode::Unavailable));
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !snapshot.descriptor.protected {
            return Err(PolicyError::new(PolicyErrorCode::Unavailable));
        }

        let mut expires_at = first.decision_expires_at;
        let mut request_digests = BTreeSet::new();
        let mut resource_digests = BTreeSet::new();
        let mut grant_ids = BTreeSet::new();
        for request in requests {
            let partition_decision = evaluate(
                snapshot,
                request,
                &state.revoked_principals,
                &state.revoked_grants,
                &state.revoked_resources,
            )?;
            let mut processor_request = request.clone();
            processor_request.resource = PolicyResource::Processor;
            validate_request(PolicyResource::Processor, &processor_request)?;
            let processor_decision = evaluate(
                snapshot,
                &processor_request,
                &state.revoked_principals,
                &state.revoked_grants,
                &state.revoked_resources,
            )?;
            if partition_decision.outcome != PolicyOutcome::Allow
                || processor_decision.outcome != PolicyOutcome::Allow
            {
                return Err(PolicyError::new(PolicyErrorCode::Revoked));
            }
            expires_at = expires_at
                .min(partition_decision.expires_at)
                .min(processor_decision.expires_at);
            request_digests.insert(retrieval_request_semantic_digest(request)?);
            resource_digests.insert(request.input_digest.clone());
            if let Some(grant_id) = request
                .capability
                .as_ref()
                .and_then(|capability| capability.grant_id.clone())
            {
                grant_ids.insert(grant_id);
            }
        }
        if expires_at <= first.observed_as_of {
            return Err(PolicyError::new(PolicyErrorCode::Revoked));
        }
        let requested_lifetime_nanos = u64::try_from(
            expires_at
                .unix_nanos()
                .checked_sub(first.observed_as_of.unix_nanos())
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?,
        )
        .map_err(|_error| PolicyError::new(PolicyErrorCode::LimitExceeded))?;
        let requested_lifetime = Duration::from_nanos(requested_lifetime_nanos);
        let proof_lifetime = requested_lifetime.min(MAX_RETRIEVAL_AUTHORIZATION_TTL);
        let monotonic_expires_at = Instant::now()
            .checked_add(proof_lifetime)
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::LimitExceeded))?;
        let processor = first
            .processor
            .clone()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
        let vector_allowed = first.required_capability == Some(Capability::CompileContext)
            && first.capability.as_ref().is_some_and(|capability| {
                capability
                    .capabilities
                    .contains(&Capability::CompileContext)
            });
        let partition_digest = retrieval_partition_digest(
            &first.principal_id,
            &first.tenant_id,
            &project_ids,
            &first.purpose,
            &processor,
            first.maximum_classification,
            first.maximum_instruction_authority,
            vector_allowed,
            &snapshot.descriptor,
            state.revocation_epoch,
            &request_digests,
        )?;
        let claims = RetrievalAuthorizationClaims {
            principal_id: first.principal_id.clone(),
            tenant_id: first.tenant_id.clone(),
            project_ids,
            purpose: first.purpose.clone(),
            processor,
            maximum_classification: first.maximum_classification,
            maximum_instruction_authority: first.maximum_instruction_authority,
            valid_at: first.valid_at,
            observed_as_of: first.observed_as_of,
            vector_allowed,
            policy_digest: snapshot.descriptor.policy_digest.clone(),
            policy_revision: snapshot.descriptor.revision,
            revocation_epoch: state.revocation_epoch,
            partition_digest,
        };
        Ok(RetrievalAuthorization {
            authority: Arc::downgrade(self),
            claims,
            grant_ids,
            resource_digests,
            request_template: first.clone(),
            monotonic_expires_at,
        })
    }

    /// Returns bounded, content-free cache measurements without tenant identifiers.
    pub fn cache_statistics(&self) -> Result<PolicyCacheStatistics, PolicyError> {
        let state = self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let mut tenant_counts = BTreeMap::<&RecordId, usize>::new();
        for key in state.cache.keys() {
            let count = tenant_counts.entry(&key.tenant_id).or_default();
            *count = count.saturating_add(1);
        }
        Ok(PolicyCacheStatistics {
            entries: state.cache.len(),
            maximum_tenant_entries: tenant_counts.values().copied().max().unwrap_or(0),
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            capacity_evictions: self.cache_capacity_evictions.load(Ordering::Relaxed),
            expired_evictions: self.cache_expired_evictions.load(Ordering::Relaxed),
        })
    }

    /// Parses strict canonical JSON, compiles its rule DAG, and installs it atomically.
    pub fn install_json(
        &self,
        bytes: &[u8],
        activated_at: UtcTimestamp,
    ) -> Result<PolicySnapshot, PolicyError> {
        let profile: PolicyProfile = serde_json::from_slice(bytes)
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
        self.install(profile, activated_at)
    }

    /// Parses human-authored TOML and compiles the identical canonical profile semantics.
    pub fn install_toml(
        &self,
        text: &str,
        activated_at: UtcTimestamp,
    ) -> Result<PolicySnapshot, PolicyError> {
        let profile: PolicyProfile = toml::from_str(text)
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
        self.install(profile, activated_at)
    }

    /// Compiles, hashes, and atomically installs one immutable profile snapshot.
    pub fn install(
        &self,
        profile: PolicyProfile,
        activated_at: UtcTimestamp,
    ) -> Result<PolicySnapshot, PolicyError> {
        let rules = compile_rules(&profile)?;
        let policy_digest = profile_digest(&profile)?;
        let descriptor = PolicySnapshot {
            revision: profile.revision,
            policy_digest,
            activated_at,
            protected: profile.protected,
        };
        let mut state = self
            .state
            .write()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if state
            .snapshot
            .as_ref()
            .is_some_and(|current| current.descriptor.revision >= descriptor.revision)
        {
            return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
        }
        let previous_policy_digest = state
            .snapshot
            .as_ref()
            .map(|current| current.descriptor.policy_digest.clone());
        state.revocation_epoch = state
            .revocation_epoch
            .checked_add(1)
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::LimitExceeded))?;
        let sequence = state.revocation_epoch;
        state.snapshot = Some(CompiledSnapshot {
            descriptor: descriptor.clone(),
            rules,
        });
        state.available = true;
        state.cache.clear();
        state.invalidations.push(PolicyInvalidationEvent {
            sequence,
            previous_policy_digest,
            policy_digest: descriptor.policy_digest.clone(),
            reason: PolicyInvalidationReason::PolicyChanged,
            occurred_at: activated_at,
        });
        Ok(descriptor)
    }

    /// Simulates a required policy dependency outage; protected calls then fail closed.
    pub fn set_available(&self, available: bool) -> Result<(), PolicyError> {
        self.state
            .write()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?
            .available = available;
        Ok(())
    }

    /// Immediately revokes one principal before background invalidation completes.
    pub fn revoke_principal(
        &self,
        principal: RecordId,
        occurred_at: UtcTimestamp,
    ) -> Result<PolicyInvalidationEvent, PolicyError> {
        self.revoke(Revocation::Principal(principal), occurred_at)
    }

    /// Immediately revokes one signed capability grant.
    pub fn revoke_grant(
        &self,
        grant: RecordId,
        occurred_at: UtcTimestamp,
    ) -> Result<PolicyInvalidationEvent, PolicyError> {
        self.revoke(Revocation::Grant(grant), occurred_at)
    }

    /// Immediately revokes one exact normalized resource input.
    pub fn revoke_resource(
        &self,
        resource: ContentDigest,
        occurred_at: UtcTimestamp,
    ) -> Result<PolicyInvalidationEvent, PolicyError> {
        self.revoke(Revocation::Resource(resource), occurred_at)
    }

    /// Returns current grant revocations for signature resolution.
    pub fn revoked_grants(&self) -> Result<BTreeSet<RecordId>, PolicyError> {
        Ok(self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?
            .revoked_grants
            .clone())
    }

    /// Returns current principal revocations for downstream signature and handoff verification.
    pub fn revoked_principals(&self) -> Result<BTreeSet<RecordId>, PolicyError> {
        Ok(self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?
            .revoked_principals
            .clone())
    }

    /// Returns ordered high-priority policy/revocation invalidation events.
    pub fn invalidations(&self) -> Result<Vec<PolicyInvalidationEvent>, PolicyError> {
        Ok(self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?
            .invalidations
            .clone())
    }

    fn revoke(
        &self,
        revocation: Revocation,
        occurred_at: UtcTimestamp,
    ) -> Result<PolicyInvalidationEvent, PolicyError> {
        let mut state = self
            .state
            .write()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let policy_digest = snapshot.descriptor.policy_digest.clone();
        match revocation {
            Revocation::Principal(value) => {
                state.revoked_principals.insert(value);
            }
            Revocation::Grant(value) => {
                state.revoked_grants.insert(value);
            }
            Revocation::Resource(value) => {
                state.revoked_resources.insert(value);
            }
        }
        state.revocation_epoch = state
            .revocation_epoch
            .checked_add(1)
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::LimitExceeded))?;
        let event = PolicyInvalidationEvent {
            sequence: state.revocation_epoch,
            previous_policy_digest: Some(policy_digest.clone()),
            policy_digest,
            reason: PolicyInvalidationReason::Revoked,
            occurred_at,
        };
        state.cache.clear();
        state.invalidations.push(event.clone());
        Ok(event)
    }

    fn authorize(
        &self,
        expected_resource: PolicyResource,
        request: &PolicyRequest,
    ) -> Result<PolicyDecision, PolicyError> {
        validate_request(expected_resource, request)?;
        let request_digest = request_digest(request)?;
        {
            let state = self
                .state
                .read()
                .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
            if !state.available {
                return Err(PolicyError::new(PolicyErrorCode::Unavailable));
            }
            let snapshot = state
                .snapshot
                .as_ref()
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
            let key = CacheKey {
                tenant_id: request.tenant_id.clone(),
                request_digest: request_digest.clone(),
                policy_digest: snapshot.descriptor.policy_digest.clone(),
                revocation_epoch: state.revocation_epoch,
            };
            if let Some(decision) = state
                .cache
                .get(&key)
                .filter(|decision| decision.expires_at > request.observed_as_of)
            {
                increment_counter(&self.cache_hits, 1);
                return Ok(decision.clone());
            }
        }
        let mut state = self
            .state
            .write()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !state.available {
            return Err(PolicyError::new(PolicyErrorCode::Unavailable));
        }
        let snapshot = state
            .snapshot
            .clone()
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))?;
        let key = CacheKey {
            tenant_id: request.tenant_id.clone(),
            request_digest,
            policy_digest: snapshot.descriptor.policy_digest.clone(),
            revocation_epoch: state.revocation_epoch,
        };
        let prior_len = state.cache.len();
        state
            .cache
            .retain(|_key, decision| decision.expires_at > request.observed_as_of);
        increment_counter(
            &self.cache_expired_evictions,
            prior_len.saturating_sub(state.cache.len()),
        );
        if let Some(decision) = state.cache.get(&key) {
            increment_counter(&self.cache_hits, 1);
            return Ok(decision.clone());
        }
        increment_counter(&self.cache_misses, 1);
        let decision = evaluate(
            &snapshot,
            request,
            &state.revoked_principals,
            &state.revoked_grants,
            &state.revoked_resources,
        )?;
        let mut capacity_evictions = 0usize;
        while state
            .cache
            .keys()
            .filter(|candidate| candidate.tenant_id == request.tenant_id)
            .count()
            >= MAX_POLICY_CACHE_ENTRIES_PER_TENANT
        {
            let Some(oldest_key) = state
                .cache
                .keys()
                .find(|candidate| candidate.tenant_id == request.tenant_id)
                .cloned()
            else {
                break;
            };
            state.cache.remove(&oldest_key);
            capacity_evictions = capacity_evictions.saturating_add(1);
        }
        while state.cache.len() >= MAX_POLICY_CACHE_ENTRIES {
            if state.cache.pop_first().is_none() {
                break;
            }
            capacity_evictions = capacity_evictions.saturating_add(1);
        }
        increment_counter(&self.cache_capacity_evictions, capacity_evictions);
        state.cache.insert(key, decision.clone());
        Ok(decision)
    }
}

fn increment_counter(counter: &AtomicU64, amount: usize) {
    let amount = u64::try_from(amount).unwrap_or(u64::MAX);
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

enum Revocation {
    Principal(RecordId),
    Grant(RecordId),
    Resource(ContentDigest),
}

impl PolicyEngine for CompiledPolicyEngine {
    fn snapshot(&self) -> Result<PolicySnapshot, PolicyError> {
        let state = self
            .state
            .read()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::Unavailable))?;
        if !state.available {
            return Err(PolicyError::new(PolicyErrorCode::Unavailable));
        }
        state
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.descriptor.clone())
            .ok_or_else(|| PolicyError::new(PolicyErrorCode::Unavailable))
    }

    fn authorize_partition(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Partition, request)
    }

    fn authorize_metadata(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Metadata, request)
    }

    fn authorize_content(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Content, request)
    }

    fn authorize_processor(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Processor, request)
    }

    fn authorize_bundle(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Bundle, request)
    }

    fn authorize_handoff(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Handoff, request)
    }

    fn authorize_effect(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        self.authorize(PolicyResource::Effect, request)
    }
}

fn compile_rules(profile: &PolicyProfile) -> Result<Vec<PolicyRule>, PolicyError> {
    if profile.schema_version != "cigar.policy-profile.v1" || profile.revision == 0 {
        return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
    }
    if profile.rules.len() > crate::MAX_POLICY_RULES {
        return Err(PolicyError::new(PolicyErrorCode::LimitExceeded));
    }
    let mut by_id = BTreeMap::new();
    for rule in &profile.rules {
        validate_rule(rule)?;
        if by_id.insert(rule.id.clone(), rule.clone()).is_some() {
            return Err(PolicyError::new(PolicyErrorCode::InvalidRuleGraph));
        }
    }
    for rule in by_id.values() {
        if rule
            .depends_on
            .iter()
            .any(|dependency| !by_id.contains_key(dependency) || dependency == &rule.id)
        {
            return Err(PolicyError::new(PolicyErrorCode::InvalidRuleGraph));
        }
    }
    let mut remaining: BTreeSet<_> = by_id.keys().cloned().collect();
    let mut emitted = BTreeSet::new();
    let mut ordered = Vec::with_capacity(by_id.len());
    while !remaining.is_empty() {
        let mut ready: Vec<_> = remaining
            .iter()
            .filter_map(|id| {
                let rule = by_id.get(id)?;
                rule.depends_on
                    .is_subset(&emitted)
                    .then(|| (rule.priority, id.clone()))
            })
            .collect();
        ready.sort();
        let Some((_priority, id)) = ready.into_iter().next() else {
            return Err(PolicyError::new(PolicyErrorCode::InvalidRuleGraph));
        };
        remaining.remove(&id);
        emitted.insert(id.clone());
        ordered.push(
            by_id
                .get(&id)
                .cloned()
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidRuleGraph))?,
        );
    }
    Ok(ordered)
}

fn validate_rule(rule: &PolicyRule) -> Result<(), PolicyError> {
    let text_valid = |value: &str| {
        !value.is_empty()
            && value.len() <= crate::MAX_POLICY_TEXT_BYTES
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    if !text_valid(&rule.id)
        || rule.depends_on.len() > crate::MAX_POLICY_SELECTORS
        || rule.resources.len() > crate::MAX_POLICY_SELECTORS
        || rule.principal_ids.len() > crate::MAX_POLICY_SELECTORS
        || rule.tenant_ids.len() > crate::MAX_POLICY_SELECTORS
        || rule.project_ids.len() > crate::MAX_POLICY_SELECTORS
        || rule.purposes.len() > crate::MAX_POLICY_SELECTORS
        || rule.processors.len() > crate::MAX_POLICY_SELECTORS
        || rule.redaction_paths.len() > crate::MAX_POLICY_SELECTORS
        || rule.conditions.len() > crate::MAX_POLICY_SELECTORS
        || (rule.action == PolicyOutcome::Redact && rule.redaction_paths.is_empty())
        || (rule.action != PolicyOutcome::Redact && !rule.redaction_paths.is_empty())
        || rule
            .depends_on
            .iter()
            .chain(rule.purposes.iter())
            .chain(rule.processors.iter())
            .chain(rule.conditions.iter())
            .any(|value| !text_valid(value))
        || rule
            .redaction_paths
            .iter()
            .any(|path| !text_valid(path) || !path.starts_with('/') || path.contains("//"))
    {
        Err(PolicyError::new(PolicyErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn validate_request(
    expected_resource: PolicyResource,
    request: &PolicyRequest,
) -> Result<(), PolicyError> {
    let valid_text = |value: &str| {
        !value.is_empty()
            && value.len() <= crate::MAX_POLICY_TEXT_BYTES
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    if request.resource != expected_resource
        || !valid_text(&request.purpose)
        || request
            .processor
            .as_ref()
            .is_some_and(|processor| !valid_text(processor))
        || request.allowed_project_ids.len() > crate::MAX_POLICY_SELECTORS
        || request.allowed_purposes.len() > crate::MAX_POLICY_SELECTORS
        || request.allowed_processors.len() > crate::MAX_POLICY_SELECTORS
        || request.decision_expires_at <= request.observed_as_of
    {
        Err(PolicyError::new(PolicyErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn evaluate(
    snapshot: &CompiledSnapshot,
    request: &PolicyRequest,
    revoked_principals: &BTreeSet<RecordId>,
    revoked_grants: &BTreeSet<RecordId>,
    revoked_resources: &BTreeSet<ContentDigest>,
) -> Result<PolicyDecision, PolicyError> {
    if revoked_principals.contains(&request.principal_id)
        || revoked_resources.contains(&request.input_digest)
        || request
            .capability
            .as_ref()
            .and_then(|capability| capability.grant_id.as_ref())
            .is_some_and(|grant| revoked_grants.contains(grant))
    {
        return Ok(decision(
            snapshot,
            request,
            PolicyOutcome::Deny,
            PolicyReason::Revoked,
            DisclosureClass::DeniedExistence,
            BTreeSet::new(),
            BTreeSet::new(),
        ));
    }
    if matches!(
        request.resource,
        PolicyResource::Bundle | PolicyResource::Handoff | PolicyResource::Effect
    ) && request.bound_policy_digest.as_ref() != Some(&snapshot.descriptor.policy_digest)
    {
        return Ok(decision(
            snapshot,
            request,
            PolicyOutcome::RequireRefresh,
            PolicyReason::PolicyChanged,
            DisclosureClass::CallerVisible,
            BTreeSet::new(),
            BTreeSet::new(),
        ));
    }
    if request.tenant_id != request.authenticated_tenant_id {
        return Ok(hard_deny(snapshot, request, PolicyReason::TenantMismatch));
    }
    if request.project_id.as_ref().is_some_and(|project| {
        !request.allowed_project_ids.contains(project)
            || request
                .capability
                .as_ref()
                .is_some_and(|capability| !capability.project_ids.contains(project))
    }) {
        return Ok(hard_deny(snapshot, request, PolicyReason::ScopeDenied));
    }
    if !request.principal_active {
        return Ok(hard_deny(snapshot, request, PolicyReason::PrincipalDenied));
    }
    if !capability_allows(request) {
        return Ok(hard_deny(snapshot, request, PolicyReason::CapabilityDenied));
    }
    if !request.allowed_purposes.contains("*")
        && !request.allowed_purposes.contains(&request.purpose)
    {
        return Ok(hard_deny(snapshot, request, PolicyReason::PurposeDenied));
    }
    if request.processor.as_ref().is_some_and(|processor| {
        (!request.allowed_processors.contains("*")
            && !request.allowed_processors.contains(processor))
            || request.capability.as_ref().is_some_and(|capability| {
                !capability.processors.is_empty() && !capability.processors.contains(processor)
            })
    }) {
        return Ok(hard_deny(snapshot, request, PolicyReason::ProcessorDenied));
    }
    if request.classification > request.maximum_classification
        || !request.residency_allowed
        || !request.egress_allowed
    {
        return Ok(hard_deny(
            snapshot,
            request,
            PolicyReason::ClassificationDenied,
        ));
    }
    if !request.integrity_verified || request.lifecycle != Lifecycle::Active {
        let outcome = if request.lifecycle == Lifecycle::Quarantined || !request.integrity_verified
        {
            PolicyOutcome::Quarantine
        } else {
            PolicyOutcome::Deny
        };
        return Ok(decision(
            snapshot,
            request,
            outcome,
            PolicyReason::IntegrityDenied,
            DisclosureClass::DeniedExistence,
            BTreeSet::new(),
            BTreeSet::new(),
        ));
    }
    if request.valid_at < request.valid_from
        || request
            .valid_until
            .is_some_and(|valid_until| request.valid_at >= valid_until)
        || request.observed_at > request.observed_as_of
        || request
            .freshness_expires_at
            .is_some_and(|expires| request.observed_as_of >= expires)
    {
        return Ok(hard_deny(snapshot, request, PolicyReason::TemporalDenied));
    }
    if request.instruction_authority > request.maximum_instruction_authority {
        return Ok(hard_deny(
            snapshot,
            request,
            PolicyReason::InstructionAuthorityDenied,
        ));
    }
    if request.excluded || !request.modality_supported {
        return Ok(hard_deny(snapshot, request, PolicyReason::ContractDenied));
    }
    if request.resource == PolicyResource::Effect
        && (!request.effect_constraints_satisfied
            || request.fencing_required && !request.fencing_verified
            || matches!(
                request.effect_risk,
                Some(RiskLevel::High | RiskLevel::Critical)
            ) && !request.effect_approved)
    {
        return Ok(decision(
            snapshot,
            request,
            if request.effect_approved {
                PolicyOutcome::Deny
            } else {
                PolicyOutcome::RequireApproval
            },
            PolicyReason::EffectDenied,
            DisclosureClass::CallerVisible,
            BTreeSet::new(),
            BTreeSet::new(),
        ));
    }

    let mut outcome = PolicyOutcome::Allow;
    let mut redactions = BTreeSet::new();
    let mut conditions = BTreeSet::new();
    let mut rule_matched = false;
    for rule in &snapshot.rules {
        if rule_matches(rule, request) {
            rule_matched = true;
            outcome = outcome.min(rule.action);
            if rule.action == PolicyOutcome::Redact {
                redactions.extend(rule.redaction_paths.iter().cloned());
            }
            conditions.extend(rule.conditions.iter().cloned());
        }
    }
    let reason = if rule_matched && outcome != PolicyOutcome::Allow {
        PolicyReason::DeclarativeRule
    } else {
        PolicyReason::Allowed
    };
    let disclosure = if matches!(outcome, PolicyOutcome::Deny | PolicyOutcome::Quarantine) {
        DisclosureClass::DeniedExistence
    } else {
        DisclosureClass::CallerVisible
    };
    Ok(decision(
        snapshot, request, outcome, reason, disclosure, redactions, conditions,
    ))
}

fn capability_allows(request: &PolicyRequest) -> bool {
    match (request.required_capability, request.capability.as_ref()) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(required), Some(capability)) => {
            capability.subject_id == request.principal_id
                && capability.expires_at > request.observed_as_of
                && capability.capabilities.contains(&required)
        }
    }
}

fn rule_matches(rule: &PolicyRule, request: &PolicyRequest) -> bool {
    (rule.resources.is_empty() || rule.resources.contains(&request.resource))
        && (rule.principal_ids.is_empty() || rule.principal_ids.contains(&request.principal_id))
        && (rule.tenant_ids.is_empty() || rule.tenant_ids.contains(&request.tenant_id))
        && (rule.project_ids.is_empty()
            || request
                .project_id
                .as_ref()
                .is_some_and(|project| rule.project_ids.contains(project)))
        && (rule.purposes.is_empty() || rule.purposes.contains(&request.purpose))
        && (rule.processors.is_empty()
            || request
                .processor
                .as_ref()
                .is_some_and(|processor| rule.processors.contains(processor)))
        && rule
            .classification_at_least
            .is_none_or(|minimum| request.classification >= minimum)
}

fn hard_deny(
    snapshot: &CompiledSnapshot,
    request: &PolicyRequest,
    reason: PolicyReason,
) -> PolicyDecision {
    decision(
        snapshot,
        request,
        PolicyOutcome::Deny,
        reason,
        DisclosureClass::DeniedExistence,
        BTreeSet::new(),
        BTreeSet::new(),
    )
}

fn decision(
    snapshot: &CompiledSnapshot,
    request: &PolicyRequest,
    outcome: PolicyOutcome,
    reason: PolicyReason,
    disclosure: DisclosureClass,
    redaction_paths: BTreeSet<String>,
    conditions: BTreeSet<String>,
) -> PolicyDecision {
    let expires_at = [
        request.valid_until,
        request.freshness_expires_at,
        request
            .capability
            .as_ref()
            .map(|capability| capability.expires_at),
        Some(request.decision_expires_at),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(request.decision_expires_at);
    PolicyDecision {
        outcome,
        reason,
        input_digest: request.input_digest.clone(),
        policy_digest: snapshot.descriptor.policy_digest.clone(),
        redaction_paths,
        conditions,
        expires_at,
        disclosure,
        timing_class: if matches!(outcome, PolicyOutcome::Deny | PolicyOutcome::Quarantine) {
            TimingClass::Denied
        } else {
            TimingClass::Eligible
        },
    }
}

fn profile_digest(profile: &PolicyProfile) -> Result<ContentDigest, PolicyError> {
    let json = serde_json::to_vec(profile)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    let node = parse_strict_json(&json)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    let cbor = to_deterministic_cbor(&node)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    digest_parts(b"CIGAR-POLICY-PROFILE\0v1\0", &[&cbor])
}

#[allow(clippy::too_many_arguments)]
fn retrieval_partition_digest(
    principal_id: &RecordId,
    tenant_id: &RecordId,
    project_ids: &BTreeSet<RecordId>,
    purpose: &str,
    processor: &str,
    maximum_classification: cigar_protocol::Classification,
    maximum_instruction_authority: cigar_protocol::InstructionAuthority,
    vector_allowed: bool,
    snapshot: &PolicySnapshot,
    revocation_epoch: u64,
    request_digests: &BTreeSet<ContentDigest>,
) -> Result<ContentDigest, PolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-RETRIEVAL-AUTHORIZATION\0v2\0");
    hash_field(&mut hasher, b"principal", principal_id.as_str().as_bytes());
    hash_field(&mut hasher, b"tenant", tenant_id.as_str().as_bytes());
    for project_id in project_ids {
        hash_field(&mut hasher, b"project", project_id.as_str().as_bytes());
    }
    hash_field(&mut hasher, b"purpose", purpose.as_bytes());
    hash_field(&mut hasher, b"processor", processor.as_bytes());
    hash_field(
        &mut hasher,
        b"maximum_classification",
        format!("{maximum_classification:?}").as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"maximum_instruction_authority",
        format!("{maximum_instruction_authority:?}").as_bytes(),
    );
    hash_field(&mut hasher, b"vector_allowed", &[u8::from(vector_allowed)]);
    hash_field(
        &mut hasher,
        b"policy_digest",
        snapshot.policy_digest.as_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"policy_revision",
        &snapshot.revision.to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"revocation_epoch",
        &revocation_epoch.to_be_bytes(),
    );
    for request_digest in request_digests {
        hash_field(
            &mut hasher,
            b"request_digest",
            request_digest.as_str().as_bytes(),
        );
    }
    let bytes = hasher.finalize();
    digest_parts(b"CIGAR-RETRIEVAL-PARTITION\0v2\0", &[&bytes])
}

fn retrieval_request_semantic_digest(
    request: &PolicyRequest,
) -> Result<ContentDigest, PolicyError> {
    let mut stable = request.clone();
    stable.valid_at = stable.valid_from;
    stable.observed_at = stable.valid_from;
    stable.observed_as_of = stable.valid_from;
    stable.decision_expires_at = stable.valid_until.unwrap_or(stable.valid_from);
    let digest = request_digest(&stable)?;
    digest_parts(
        b"CIGAR-RETRIEVAL-REQUEST-SEMANTICS\0v1\0",
        &[digest.as_str().as_bytes()],
    )
}

fn request_digest(request: &PolicyRequest) -> Result<ContentDigest, PolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-POLICY-REQUEST\0v1\0");
    hash_field(
        &mut hasher,
        b"resource",
        format!("{:?}", request.resource).as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"input",
        request.input_digest.as_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"principal",
        request.principal_id.as_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"tenant",
        request.tenant_id.as_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"authenticated_tenant",
        request.authenticated_tenant_id.as_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"principal_active",
        &[u8::from(request.principal_active)],
    );
    hash_field(&mut hasher, b"purpose", request.purpose.as_bytes());
    hash_field(
        &mut hasher,
        b"project",
        request
            .project_id
            .as_ref()
            .map_or(&[], |value| value.as_str().as_bytes()),
    );
    hash_field(
        &mut hasher,
        b"processor",
        request.processor.as_ref().map_or(&[], String::as_bytes),
    );
    for project in &request.allowed_project_ids {
        hash_field(&mut hasher, b"allowed_project", project.as_str().as_bytes());
    }
    for purpose in &request.allowed_purposes {
        hash_field(&mut hasher, b"allowed_purpose", purpose.as_bytes());
    }
    for processor in &request.allowed_processors {
        hash_field(&mut hasher, b"allowed_processor", processor.as_bytes());
    }
    hash_field(
        &mut hasher,
        b"valid_at",
        &request.valid_at.unix_nanos().to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"valid_from",
        &request.valid_from.unix_nanos().to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"valid_until",
        request
            .valid_until
            .map(|value| value.unix_nanos().to_be_bytes())
            .as_ref()
            .map_or(&[], <[u8; 16]>::as_slice),
    );
    hash_field(
        &mut hasher,
        b"observed_at",
        &request.observed_at.unix_nanos().to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"observed_as_of",
        &request.observed_as_of.unix_nanos().to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"freshness_expires_at",
        request
            .freshness_expires_at
            .map(|value| value.unix_nanos().to_be_bytes())
            .as_ref()
            .map_or(&[], <[u8; 16]>::as_slice),
    );
    hash_field(
        &mut hasher,
        b"decision_expires_at",
        &request.decision_expires_at.unix_nanos().to_be_bytes(),
    );
    for (label, value) in [
        (
            b"classification".as_slice(),
            format!("{:?}", request.classification),
        ),
        (
            b"maximum_classification".as_slice(),
            format!("{:?}", request.maximum_classification),
        ),
        (b"lifecycle".as_slice(), format!("{:?}", request.lifecycle)),
        (
            b"instruction_authority".as_slice(),
            format!("{:?}", request.instruction_authority),
        ),
        (
            b"maximum_instruction_authority".as_slice(),
            format!("{:?}", request.maximum_instruction_authority),
        ),
    ] {
        hash_field(&mut hasher, label, value.as_bytes());
    }
    hash_field(
        &mut hasher,
        b"flags",
        &[
            u8::from(request.integrity_verified),
            u8::from(request.residency_allowed),
            u8::from(request.egress_allowed),
            u8::from(request.excluded),
            u8::from(request.modality_supported),
            u8::from(request.effect_approved),
            u8::from(request.effect_constraints_satisfied),
            u8::from(request.fencing_required),
            u8::from(request.fencing_verified),
        ],
    );
    if let Some(required) = request.required_capability {
        hash_field(
            &mut hasher,
            b"required_capability",
            format!("{required:?}").as_bytes(),
        );
    }
    if let Some(capability) = &request.capability {
        hash_field(
            &mut hasher,
            b"capability_subject",
            capability.subject_id.as_str().as_bytes(),
        );
        if let Some(grant_id) = &capability.grant_id {
            hash_field(
                &mut hasher,
                b"capability_grant",
                grant_id.as_str().as_bytes(),
            );
        }
        for value in &capability.capabilities {
            hash_field(
                &mut hasher,
                b"effective_capability",
                format!("{value:?}").as_bytes(),
            );
        }
        for project in &capability.project_ids {
            hash_field(
                &mut hasher,
                b"capability_project",
                project.as_str().as_bytes(),
            );
        }
        for processor in &capability.processors {
            hash_field(&mut hasher, b"capability_processor", processor.as_bytes());
        }
        hash_field(
            &mut hasher,
            b"capability_expires_at",
            &capability.expires_at.unix_nanos().to_be_bytes(),
        );
    }
    if let Some(bound_policy_digest) = &request.bound_policy_digest {
        hash_field(
            &mut hasher,
            b"bound_policy_digest",
            bound_policy_digest.as_str().as_bytes(),
        );
    }
    if let Some(risk) = request.effect_risk {
        hash_field(&mut hasher, b"effect_risk", format!("{risk:?}").as_bytes());
    }
    let bytes = hasher.finalize();
    digest_parts(b"CIGAR-POLICY-CACHE-KEY\0v1\0", &[&bytes])
}

fn hash_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update(label.len().to_be_bytes());
    hasher.update(label);
    hasher.update(value.len().to_be_bytes());
    hasher.update(value);
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<ContentDigest, PolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    }
    ContentDigest::new(value).map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))
}
