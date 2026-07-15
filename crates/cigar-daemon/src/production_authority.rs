//! Explicit, fail-closed production authority shared by domain application adapters.
//!
//! Transport authentication proves a subject. This module applies the distinct server-owned
//! mapping from that subject's resolved domain identity to projects, capabilities, roles,
//! processors, signing keys, and current compiled policy. No request payload can add authority.

use crate::{
    AuthorityClock, CatalogContextAuthorization, CatalogContextAuthorizationError,
    CatalogContextAuthorizer, CurrentSpaceHandoffAuthorization, DomainAuthorizationError,
    DomainIdentityError, DomainIdentityErrorCode, DomainIdentityResolver,
    DurableSnapshotAuthenticator, DurableSnapshotError, DurableSnapshotErrorCode,
    EffectPolicyAction, EffectPolicyDecision, EffectPolicyEvaluator, EffectPolicyFailure,
    EffectRecordSignature, EffectRecordSignatureAuthority, EffectWorkerAction,
    EffectWorkerAuthority, EffectWorkerAuthorityError, HandoffResultMergePlanner, LifecycleError,
    OperatorAuthorizer, ProductionTenantProvider, ResolvedDomainIdentity,
    SNAPSHOT_ROOT_SIGNATURE_PURPOSE, SNAPSHOT_ROOT_SIGNER, SnapshotRootAuthentication,
    SpaceHandoffAuthorizationScope, SpaceHandoffAuthorizer, SpaceHandoffDependencyError,
};
use cigar_api::{AuthenticatedIdentity, PrincipalId, RequestContext, TenantId};
use cigar_canon::parse_strict_json;
use cigar_crypto::{
    KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, KeyStatus, SignatureEnvelope, SignatureRequest,
    SignatureVerification,
};
use cigar_effects::{DurableEffectRecord, EffectAuthorization, EffectError, EffectErrorCode};
use cigar_policy::{
    CapabilityContext, CompiledPolicyEngine, EffectiveCapabilities, PolicyDecision, PolicyEngine,
    PolicyError, PolicyErrorCode, PolicyOutcome, PolicyRequest, PolicyResource, PolicySnapshot,
};
use cigar_protocol::{
    ApprovalKind, Capability, Classification, ContentDigest, ContextContract, EffectIntent,
    InstructionAuthority, Lifecycle, RecordId, RiskLevel, UtcTimestamp, VersionId,
};
use cigar_space::{HandoffMergeMaterial, ResourceKey, ResultMergeKind, ResultMergeMapping};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

const AUTHORITY_SCHEMA: &str = "cigar.production-authority.v1";
const MAX_AUTHORITY_JSON_BYTES: usize = 1_048_576;
const MAX_TENANTS: usize = 1_024;
const MAX_PROJECTS_PER_TENANT: usize = 1_024;
const MAX_PRINCIPALS_PER_TENANT: usize = 10_000;
const MAX_EFFECT_RULES_PER_PRINCIPAL: usize = 1_024;
const MAX_ROLES_PER_PRINCIPAL: usize = 256;
const MAX_PROJECTS_PER_PRINCIPAL: usize = 256;
const MAX_PURPOSES_PER_PRINCIPAL: usize = 1_024;
const MAX_PROCESSORS_PER_PRINCIPAL: usize = 1_024;
const MAX_REVOKED_KEYS_PER_TENANT: usize = 1_024;
const MAX_TEXT_BYTES: usize = 256;
const MAX_DECISION_TTL_SECONDS: u32 = 3_600;
const EFFECT_RECORD_SIGNER: &str = "cigard-effect-kernel";
const EFFECT_RECORD_SIGNATURE_PURPOSE: &str = "cigar.effect-record.v1";

/// Stable content-free failure while loading trusted production authority state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionAuthorityErrorCode {
    /// The document or one authority relationship was malformed or contradictory.
    InvalidConfiguration,
    /// A configured collection or byte limit was exceeded.
    LimitExceeded,
    /// The mandatory protected policy snapshot was unavailable.
    PolicyUnavailable,
    /// A mandatory active tenant signing key could not be resolved.
    KeyUnavailable,
    /// The atomically replaceable authority state could not be accessed.
    StateUnavailable,
}

/// Content-free production authority construction or reload failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionAuthorityError {
    code: ProductionAuthorityErrorCode,
}

impl ProductionAuthorityError {
    const fn new(code: ProductionAuthorityErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ProductionAuthorityErrorCode {
        self.code
    }
}

impl fmt::Debug for ProductionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionAuthorityError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ProductionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "production authority configuration failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for ProductionAuthorityError {}

/// Effect actions permitted by one exact trusted connector rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredEffectAction {
    /// Persist a new intent.
    Prepare,
    /// Bind approval and authorize dispatch.
    Authorize,
    /// Claim and perform one fenced dispatch.
    Dispatch,
    /// Read a disclosure-safe status.
    Read,
    /// Reconcile an unknown external outcome.
    Reconcile,
    /// Link a separately authorized compensation intent.
    Compensate,
}

impl From<EffectPolicyAction> for ConfiguredEffectAction {
    fn from(value: EffectPolicyAction) -> Self {
        match value {
            EffectPolicyAction::Prepare => Self::Prepare,
            EffectPolicyAction::Authorize => Self::Authorize,
            EffectPolicyAction::Dispatch => Self::Dispatch,
            EffectPolicyAction::Read => Self::Read,
            EffectPolicyAction::Reconcile => Self::Reconcile,
            EffectPolicyAction::Compensate => Self::Compensate,
        }
    }
}

/// Exact connector/operation/target authority; wildcard rules are deliberately unsupported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEffectAuthorityRule {
    /// Exact registered connector identity.
    pub connector: String,
    /// Exact connector operation.
    pub operation: String,
    /// Exact bounded external target selector.
    pub target: String,
    /// Server-approved capability that the immutable intent must require.
    pub required_capability: Capability,
    /// Greatest risk accepted by this rule.
    pub maximum_risk: RiskLevel,
    /// Exact effect state-machine actions allowed for this selector.
    pub allowed_actions: Vec<ConfiguredEffectAction>,
    /// Approval provenance accepted when authorization supplies an approval.
    pub allowed_approval_kinds: Vec<ApprovalKind>,
}

/// Explicit current grant for one resolved and one transport-authenticated principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionPrincipalAuthority {
    /// Exact transport principal selector, used only by shared operator authorization.
    pub authenticated_principal: String,
    /// Stable server-resolved domain principal.
    pub principal_id: RecordId,
    /// Stable grant identity used by policy revocation checks.
    pub grant_id: RecordId,
    /// Current administrative activation state.
    pub active: bool,
    /// Whether this exact tenant/principal may call operator-only operations.
    pub operator: bool,
    /// Inclusive authority start.
    pub not_before: UtcTimestamp,
    /// Exclusive authority expiry.
    pub expires_at: UtcTimestamp,
    /// Exact current recipient roles.
    pub roles: Vec<String>,
    /// Exact projects visible to the principal.
    pub project_ids: Vec<RecordId>,
    /// Exact effective capabilities.
    pub capabilities: Vec<Capability>,
    /// Capabilities current handoff policy permits this principal to delegate or accept.
    pub delegatable_capabilities: Vec<Capability>,
    /// Exact allowed use purposes, including operation IDs used by space/handoff policy.
    pub purposes: Vec<String>,
    /// Exact allowed processors and effect connector identities.
    pub processors: Vec<String>,
    /// Server-normalized purpose for catalog operations without a compilation contract.
    pub catalog_purpose: String,
    /// Server-normalized processor for catalog operations without a target profile.
    pub catalog_processor: String,
    /// Greatest information classification visible to this principal.
    pub maximum_classification: Classification,
    /// Greatest instruction authority visible to this principal.
    pub maximum_instruction_authority: InstructionAuthority,
    /// Explicit residency gate; false always denies protected evaluation.
    pub residency_allowed: bool,
    /// Explicit egress gate; false denies processors and effects.
    pub egress_allowed: bool,
    /// Whether partitioned vector retrieval is permitted.
    pub vector_allowed: bool,
    /// Whether recipient target/model compilation is currently permitted.
    pub handoff_target_allowed: bool,
    /// Exact external effect rules.
    pub effect_rules: Vec<ProductionEffectAuthorityRule>,
}

/// Explicit authority partition and signing state for one tenant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTenantAuthority {
    /// Exact transport tenant selector, used only by shared operator authorization.
    pub authenticated_tenant: String,
    /// Stable server-resolved tenant partition.
    pub tenant_id: RecordId,
    /// Whether this tenant may currently perform protected work.
    pub active: bool,
    /// Active persistent signing key used for handoff issuance.
    pub issuer_key_ref: KeyRef,
    /// Complete project universe accepted for this tenant.
    pub project_ids: Vec<RecordId>,
    /// Complete explicit principal grants.
    pub principals: Vec<ProductionPrincipalAuthority>,
    /// Current independently revoked principals disclosed to handoff verification.
    pub revoked_principal_ids: Vec<RecordId>,
    /// Current independently revoked signing key references.
    pub revoked_key_refs: Vec<KeyRef>,
}

/// Complete strict production authority document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionAuthorityConfiguration {
    /// Must be `cigar.production-authority.v1`.
    pub schema_version: String,
    /// Exact runtime audience accepted during handoff compilation.
    pub runtime_audience: String,
    /// Short exclusive validity bound for each current decision.
    pub decision_ttl_seconds: u32,
    /// Complete configured tenant set; an empty set is invalid.
    pub tenants: Vec<ProductionTenantAuthority>,
}

impl ProductionAuthorityConfiguration {
    /// Parses duplicate-key-free, bounded strict JSON without accepting unknown fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProductionAuthorityError> {
        if bytes.len() > MAX_AUTHORITY_JSON_BYTES {
            return Err(ProductionAuthorityError::new(
                ProductionAuthorityErrorCode::LimitExceeded,
            ));
        }
        parse_strict_json(bytes).map_err(|error| {
            let code = match error.code() {
                cigar_canon::CanonicalErrorCode::LimitExceeded => {
                    ProductionAuthorityErrorCode::LimitExceeded
                }
                _ => ProductionAuthorityErrorCode::InvalidConfiguration,
            };
            ProductionAuthorityError::new(code)
        })?;
        serde_json::from_slice(bytes).map_err(|_error| {
            ProductionAuthorityError::new(ProductionAuthorityErrorCode::InvalidConfiguration)
        })
    }
}

#[derive(Clone)]
struct PrincipalGrant {
    authenticated_principal: String,
    principal_id: RecordId,
    grant_id: RecordId,
    active: bool,
    operator: bool,
    not_before: UtcTimestamp,
    expires_at: UtcTimestamp,
    roles: BTreeSet<String>,
    project_ids: BTreeSet<RecordId>,
    capabilities: BTreeSet<Capability>,
    delegatable_capabilities: BTreeSet<Capability>,
    purposes: BTreeSet<String>,
    processors: BTreeSet<String>,
    catalog_purpose: String,
    catalog_processor: String,
    maximum_classification: Classification,
    maximum_instruction_authority: InstructionAuthority,
    residency_allowed: bool,
    egress_allowed: bool,
    vector_allowed: bool,
    handoff_target_allowed: bool,
    effect_rules: BTreeMap<(String, String, String), EffectRule>,
}

#[derive(Clone)]
struct EffectRule {
    required_capability: Capability,
    maximum_risk: RiskLevel,
    allowed_actions: BTreeSet<ConfiguredEffectAction>,
    allowed_approval_kinds: BTreeSet<ApprovalKind>,
}

struct EvaluatedEffectAuthority {
    policy_allows: bool,
    capabilities: BTreeSet<Capability>,
}

impl EvaluatedEffectAuthority {
    fn denied() -> Self {
        Self {
            policy_allows: false,
            capabilities: BTreeSet::new(),
        }
    }
}

#[derive(Clone)]
struct TenantGrant {
    tenant_id: RecordId,
    active: bool,
    issuer_key_ref: KeyRef,
    project_ids: BTreeSet<RecordId>,
    principals: BTreeMap<RecordId, PrincipalGrant>,
    principal_by_transport: BTreeMap<String, RecordId>,
    revoked_principal_ids: BTreeSet<RecordId>,
    revoked_key_refs: BTreeSet<KeyRef>,
}

#[derive(Clone)]
struct AuthorityState {
    runtime_audience: String,
    decision_ttl_seconds: u32,
    tenants: BTreeMap<RecordId, TenantGrant>,
    tenant_by_transport: BTreeMap<String, RecordId>,
}

/// Shared concrete production authority for catalog, context, spaces, handoffs, and effects.
pub struct ProductionDomainAuthority {
    state: RwLock<Arc<AuthorityState>>,
    policy: Arc<CompiledPolicyEngine>,
    keys: Arc<dyn KeyProvider>,
    clock: Arc<dyn AuthorityClock>,
}

impl ProductionDomainAuthority {
    /// Validates explicit configuration, the protected policy snapshot, and every signing key.
    pub fn new(
        configuration: ProductionAuthorityConfiguration,
        policy: Arc<CompiledPolicyEngine>,
        keys: Arc<dyn KeyProvider>,
        clock: Arc<dyn AuthorityClock>,
    ) -> Result<Self, ProductionAuthorityError> {
        let now = clock.now().map_err(|_error| {
            ProductionAuthorityError::new(ProductionAuthorityErrorCode::StateUnavailable)
        })?;
        require_protected_snapshot(policy.as_ref())?;
        let state = validate_configuration(configuration, keys.as_ref(), now)?;
        Ok(Self {
            state: RwLock::new(Arc::new(state)),
            policy,
            keys,
            clock,
        })
    }

    /// Parses and validates one bounded strict JSON authority document.
    pub fn from_json(
        bytes: &[u8],
        policy: Arc<CompiledPolicyEngine>,
        keys: Arc<dyn KeyProvider>,
        clock: Arc<dyn AuthorityClock>,
    ) -> Result<Self, ProductionAuthorityError> {
        Self::new(
            ProductionAuthorityConfiguration::from_json(bytes)?,
            policy,
            keys,
            clock,
        )
    }

    /// Atomically replaces authority state after complete validation; failures retain old state.
    pub fn reload(
        &self,
        configuration: ProductionAuthorityConfiguration,
    ) -> Result<(), ProductionAuthorityError> {
        let now = self.clock.now().map_err(|_error| {
            ProductionAuthorityError::new(ProductionAuthorityErrorCode::StateUnavailable)
        })?;
        require_protected_snapshot(self.policy.as_ref())?;
        let replacement = Arc::new(validate_configuration(
            configuration,
            self.keys.as_ref(),
            now,
        )?);
        *self.state.write().map_err(|_error| {
            ProductionAuthorityError::new(ProductionAuthorityErrorCode::StateUnavailable)
        })? = replacement;
        Ok(())
    }

    /// Parses and atomically installs one bounded strict JSON authority document.
    pub fn reload_json(&self, bytes: &[u8]) -> Result<(), ProductionAuthorityError> {
        self.reload(ProductionAuthorityConfiguration::from_json(bytes)?)
    }

    /// Returns every configured tenant in strict identity order from one atomic state snapshot.
    pub fn configured_tenant_ids(&self) -> Result<Vec<RecordId>, ProductionAuthorityError> {
        Ok(self.state()?.tenants.keys().cloned().collect())
    }

    /// Resolves an authenticated transport subject only when an exact configured mapping exists.
    ///
    /// `None` is a determinate denial. This lookup never allocates identities and never falls back
    /// to payload-provided tenant or principal values.
    pub fn resolve_authenticated(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Result<Option<ResolvedDomainIdentity>, ProductionAuthorityError> {
        let state = self.state()?;
        let Some(tenant_id) = state.tenant_by_transport.get(identity.tenant().as_str()) else {
            return Ok(None);
        };
        let Some(tenant) = state.tenants.get(tenant_id) else {
            return Ok(None);
        };
        let Some(principal_id) = tenant
            .principal_by_transport
            .get(identity.principal().as_str())
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
        }))
    }

    fn state(&self) -> Result<Arc<AuthorityState>, ProductionAuthorityError> {
        self.state
            .read()
            .map(|state| Arc::clone(&state))
            .map_err(|_error| {
                ProductionAuthorityError::new(ProductionAuthorityErrorCode::StateUnavailable)
            })
    }

    fn snapshot(&self) -> Result<PolicySnapshot, PolicyError> {
        let snapshot = self.policy.snapshot()?;
        if snapshot.protected {
            Ok(snapshot)
        } else {
            Err(PolicyError::new(PolicyErrorCode::Unavailable))
        }
    }

    fn principal<'a>(
        &self,
        state: &'a AuthorityState,
        identity: &ResolvedDomainIdentity,
        now: UtcTimestamp,
    ) -> Result<(&'a TenantGrant, &'a PrincipalGrant), AuthorityLookupError> {
        let tenant = state
            .tenants
            .get(&identity.tenant_id)
            .ok_or(AuthorityLookupError::Denied)?;
        let principal = tenant
            .principals
            .get(&identity.principal_id)
            .ok_or(AuthorityLookupError::Denied)?;
        if !tenant.active
            || !principal.active
            || tenant
                .revoked_principal_ids
                .contains(&identity.principal_id)
            || now < principal.not_before
            || now >= principal.expires_at
        {
            return Err(AuthorityLookupError::Denied);
        }
        Ok((tenant, principal))
    }

    #[allow(clippy::too_many_arguments)]
    fn policy_request(
        &self,
        resource: PolicyResource,
        digest: ContentDigest,
        identity: &ResolvedDomainIdentity,
        principal: &PrincipalGrant,
        project_id: Option<RecordId>,
        purpose: String,
        processor: Option<String>,
        required_capability: Option<Capability>,
        now: UtcTimestamp,
        decision_ttl_seconds: u32,
        bound_policy_digest: Option<ContentDigest>,
        effect_risk: Option<RiskLevel>,
        effect_approved: bool,
        effect_constraints_satisfied: bool,
    ) -> Result<PolicyRequest, AuthorityLookupError> {
        let decision_expires_at = add_seconds(now, decision_ttl_seconds)?.min(principal.expires_at);
        if decision_expires_at <= now {
            return Err(AuthorityLookupError::Denied);
        }
        Ok(PolicyRequest {
            resource,
            input_digest: digest,
            principal_id: identity.principal_id.clone(),
            principal_active: principal.active,
            tenant_id: identity.tenant_id.clone(),
            authenticated_tenant_id: identity.tenant_id.clone(),
            project_id,
            allowed_project_ids: principal.project_ids.clone(),
            purpose,
            allowed_purposes: principal.purposes.clone(),
            processor,
            allowed_processors: principal.processors.clone(),
            classification: Classification::Public,
            maximum_classification: principal.maximum_classification,
            residency_allowed: principal.residency_allowed,
            egress_allowed: principal.egress_allowed,
            lifecycle: Lifecycle::Active,
            integrity_verified: true,
            valid_at: now,
            valid_from: principal.not_before,
            valid_until: Some(principal.expires_at),
            observed_at: now,
            observed_as_of: now,
            freshness_expires_at: None,
            instruction_authority: InstructionAuthority::Data,
            maximum_instruction_authority: principal.maximum_instruction_authority,
            excluded: false,
            modality_supported: true,
            capability: Some(CapabilityContext {
                subject_id: identity.principal_id.clone(),
                grant_id: Some(principal.grant_id.clone()),
                capabilities: principal.capabilities.clone(),
                project_ids: principal.project_ids.clone(),
                processors: principal.processors.clone(),
                expires_at: principal.expires_at,
            }),
            required_capability,
            bound_policy_digest,
            effect_risk,
            effect_approved,
            effect_constraints_satisfied,
            fencing_required: false,
            fencing_verified: false,
            decision_expires_at,
        })
    }
}

impl ProductionDomainAuthority {
    #[allow(clippy::too_many_arguments)]
    fn catalog_authorization(
        &self,
        identity: &ResolvedDomainIdentity,
        requested_projects: BTreeSet<RecordId>,
        purpose: String,
        processor: String,
        required_capability: Capability,
        observed_at: UtcTimestamp,
        require_processor_gate: bool,
    ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
        let state = self
            .state()
            .map_err(|_error| CatalogContextAuthorizationError::Unavailable)?;
        let snapshot = self.snapshot().map_err(map_catalog_policy_failure)?;
        let (_tenant, principal) = self
            .principal(&state, identity, observed_at)
            .map_err(map_catalog_lookup)?;
        if requested_projects.is_empty()
            || !requested_projects.is_subset(&principal.project_ids)
            || !principal.capabilities.contains(&required_capability)
            || !principal.purposes.contains(&purpose)
            || !principal.processors.contains(&processor)
        {
            return Err(CatalogContextAuthorizationError::Denied);
        }
        let input = authority_digest(
            b"catalog-context",
            std::iter::once(identity.tenant_id.as_str())
                .chain(std::iter::once(identity.principal_id.as_str()))
                .chain(requested_projects.iter().map(RecordId::as_str))
                .chain([purpose.as_str(), processor.as_str()]),
        )
        .map_err(|_error| CatalogContextAuthorizationError::InvalidDecision)?;
        let mut retrieval_requests = Vec::with_capacity(requested_projects.len());
        for project in &requested_projects {
            let request = self
                .policy_request(
                    PolicyResource::Partition,
                    input.clone(),
                    identity,
                    principal,
                    Some(project.clone()),
                    purpose.clone(),
                    Some(processor.clone()),
                    Some(required_capability),
                    observed_at,
                    state.decision_ttl_seconds,
                    None,
                    None,
                    false,
                    true,
                )
                .map_err(map_catalog_lookup)?;
            require_allow(self.policy.authorize_partition(&request))
                .map_err(map_catalog_decision)?;
            if require_processor_gate {
                let mut processor_request = request.clone();
                processor_request.resource = PolicyResource::Processor;
                require_allow(self.policy.authorize_processor(&processor_request))
                    .map_err(map_catalog_decision)?;
            }
            retrieval_requests.push(request);
        }
        let retrieval_authorization = self
            .policy
            .authorize_retrieval_partition(&retrieval_requests)
            .map_err(map_catalog_policy_failure)?;
        let policy_vector_allowed = retrieval_authorization
            .revalidate()
            .map_err(map_catalog_policy_failure)?
            .vector_allowed();
        Ok(CatalogContextAuthorization {
            project_ids: requested_projects,
            purpose,
            processor,
            maximum_classification: principal.maximum_classification,
            maximum_instruction_authority: principal.maximum_instruction_authority,
            policy_digest: snapshot.policy_digest,
            vector_allowed: principal.vector_allowed && policy_vector_allowed,
            retrieval_authorization,
        })
    }

    fn space_capability(
        context: &RequestContext,
        scope: &SpaceHandoffAuthorizationScope,
    ) -> Result<Capability, DomainAuthorizationError> {
        let operation = context.operation().as_str();
        let valid_scope = matches!(
            (operation, scope),
            (
                "createSpace",
                SpaceHandoffAuthorizationScope::NewSpace { .. }
            ) | ("forkSpace", SpaceHandoffAuthorizationScope::Space { .. })
                | ("publishSpace", SpaceHandoffAuthorizationScope::Space { .. })
                | ("getSpaceLog", SpaceHandoffAuthorizationScope::Space { .. })
                | (
                    "subscribeSpaceEvents",
                    SpaceHandoffAuthorizationScope::Space { .. }
                )
                | (
                    "createSpaceCheckpoint",
                    SpaceHandoffAuthorizationScope::Space { .. }
                )
                | (
                    "listSpaceConflicts",
                    SpaceHandoffAuthorizationScope::Space { .. }
                )
                | (
                    "resolveSpaceConflict",
                    SpaceHandoffAuthorizationScope::Space { .. }
                )
                | ("createHandoff", SpaceHandoffAuthorizationScope::NewHandoff)
                | (
                    "previewHandoff",
                    SpaceHandoffAuthorizationScope::Handoff { .. }
                )
                | (
                    "acceptHandoff",
                    SpaceHandoffAuthorizationScope::Handoff { .. }
                )
                | (
                    "revokeHandoff",
                    SpaceHandoffAuthorizationScope::Handoff { .. }
                )
                | (
                    "recordHandoffResult",
                    SpaceHandoffAuthorizationScope::Handoff { .. }
                )
                | (
                    "mergeHandoff",
                    SpaceHandoffAuthorizationScope::HandoffMerge { .. }
                )
        );
        if !valid_scope {
            return Err(DomainAuthorizationError::Invalid);
        }
        match operation {
            "createSpace" | "forkSpace" | "createSpaceCheckpoint" | "recordHandoffResult" => {
                Ok(Capability::WriteOverlay)
            }
            "publishSpace" | "resolveSpaceConflict" | "mergeHandoff" => {
                Ok(Capability::PublishOverlay)
            }
            "getSpaceLog" | "subscribeSpaceEvents" | "listSpaceConflicts" => {
                Ok(Capability::ReadContext)
            }
            "createHandoff" | "revokeHandoff" => Ok(Capability::CreateHandoff),
            "previewHandoff" | "acceptHandoff" => Ok(Capability::AcceptHandoff),
            _ => Err(DomainAuthorizationError::Invalid),
        }
    }

    fn current_space_authorization(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        now: UtcTimestamp,
    ) -> Result<CurrentSpaceHandoffAuthorization, DomainAuthorizationError> {
        let state = self
            .state()
            .map_err(|_error| DomainAuthorizationError::Unavailable)?;
        if !authenticated_mapping_matches(&state, context.identity(), identity) {
            return Err(DomainAuthorizationError::Denied);
        }
        let snapshot = self.snapshot().map_err(map_domain_policy_failure)?;
        let (tenant, principal) = self
            .principal(&state, identity, now)
            .map_err(map_domain_lookup)?;
        let required = Self::space_capability(context, scope)?;
        let project_id = match scope {
            SpaceHandoffAuthorizationScope::NewSpace { project_id }
            | SpaceHandoffAuthorizationScope::Space { project_id, .. }
            | SpaceHandoffAuthorizationScope::HandoffMerge { project_id, .. } => {
                Some(project_id.clone())
            }
            SpaceHandoffAuthorizationScope::NewHandoff
            | SpaceHandoffAuthorizationScope::Handoff { .. } => None,
        };
        if !principal.capabilities.contains(&required)
            || !principal.purposes.contains(context.operation().as_str())
            || project_id.as_ref().is_some_and(|project| {
                !tenant.project_ids.contains(project) || !principal.project_ids.contains(project)
            })
            || tenant.revoked_key_refs.contains(&tenant.issuer_key_ref)
        {
            return Err(DomainAuthorizationError::Denied);
        }
        let metadata = self
            .keys
            .resolve(
                &tenant.issuer_key_ref,
                identity.tenant_id.as_str(),
                KeyPurpose::Signing,
                now.unix_nanos(),
            )
            .map_err(|_error| DomainAuthorizationError::Unavailable)?;
        if metadata.status != KeyStatus::Active {
            return Err(DomainAuthorizationError::Unavailable);
        }
        let digest = space_scope_digest(identity, context.operation().as_str(), scope)
            .map_err(|_error| DomainAuthorizationError::Invalid)?;
        let request = self
            .policy_request(
                PolicyResource::Handoff,
                digest,
                identity,
                principal,
                project_id.clone(),
                context.operation().as_str().to_owned(),
                None,
                Some(required),
                now,
                state.decision_ttl_seconds,
                Some(snapshot.policy_digest.clone()),
                None,
                false,
                true,
            )
            .map_err(map_domain_lookup)?;
        let decision =
            require_allow(self.policy.authorize_handoff(&request)).map_err(map_domain_decision)?;
        let mut revoked_principals = self
            .policy
            .revoked_principals()
            .map_err(map_domain_policy_failure)?;
        revoked_principals.extend(tenant.revoked_principal_ids.iter().cloned());
        Ok(CurrentSpaceHandoffAuthorization {
            effective: EffectiveCapabilities {
                tenant: identity.tenant_id.as_str().to_owned(),
                subject_id: identity.principal_id.clone(),
                grant_id: principal.grant_id.clone(),
                capabilities: principal.capabilities.clone(),
                project_ids: principal.project_ids.clone(),
                processors: principal.processors.clone(),
                expires_at: decision.expires_at.min(principal.expires_at),
            },
            resource_project_id: project_id,
            roles: principal.roles.clone(),
            policy_allowed_projects: principal.project_ids.clone(),
            policy_allowed_capabilities: principal.delegatable_capabilities.clone(),
            visible_projects: principal.project_ids.clone(),
            policy_digest: decision.policy_digest,
            revoked_principals,
            revoked_key_ids: tenant
                .revoked_key_refs
                .iter()
                .map(|key| key.as_str().to_owned())
                .collect(),
            issuer_key_ref: tenant.issuer_key_ref.clone(),
            runtime_audience: state.runtime_audience.clone(),
            target_allowed: principal.handoff_target_allowed,
        })
    }

    fn evaluate_effect_inner(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        action: EffectPolicyAction,
        intent: &EffectIntent,
        approval_kind: Option<ApprovalKind>,
    ) -> Result<EffectPolicyDecision, EffectPolicyFailure> {
        let now = self
            .clock
            .now()
            .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        let expected_operation = effect_action_operation(action);
        if context.operation().as_str() != expected_operation {
            return Ok(EffectPolicyDecision::new(false, BTreeSet::new()));
        }
        let evaluated = self.evaluate_effect_at(
            identity,
            action,
            intent,
            approval_kind,
            expected_operation,
            now,
            false,
            Some(context.identity()),
        )?;
        Ok(EffectPolicyDecision::new(
            evaluated.policy_allows,
            evaluated.capabilities,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_effect_at(
        &self,
        identity: &ResolvedDomainIdentity,
        action: EffectPolicyAction,
        intent: &EffectIntent,
        approval_kind: Option<ApprovalKind>,
        expected_operation: &str,
        now: UtcTimestamp,
        require_persisted_approval: bool,
        authenticated_identity: Option<&AuthenticatedIdentity>,
    ) -> Result<EvaluatedEffectAuthority, EffectPolicyFailure> {
        let state = self
            .state()
            .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        if authenticated_identity.is_some_and(|authenticated| {
            !authenticated_mapping_matches(&state, authenticated, identity)
        }) {
            return Ok(EvaluatedEffectAuthority::denied());
        }
        let snapshot = self
            .snapshot()
            .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        let Ok((_tenant, principal)) = self.principal(&state, identity, now) else {
            return Ok(EvaluatedEffectAuthority::denied());
        };
        let configured_action = ConfiguredEffectAction::from(action);
        let rule = principal.effect_rules.get(&(
            intent.connector.clone(),
            intent.operation.clone(),
            intent.target.clone(),
        ));
        let Some(rule) = rule else {
            return Ok(EvaluatedEffectAuthority::denied());
        };
        let action_capability = effect_action_capability(action);
        let approval_allowed =
            approval_kind.is_none_or(|kind| rule.allowed_approval_kinds.contains(&kind));
        let missing_required_approval = action == EffectPolicyAction::Authorize
            && intent.risk != RiskLevel::Low
            && approval_kind.is_none();
        let missing_persisted_approval = require_persisted_approval
            && action == EffectPolicyAction::Dispatch
            && intent.risk != RiskLevel::Low
            && approval_kind.is_none();
        if now < intent.created_at
            || now >= intent.expires_at
            || !rule.allowed_actions.contains(&configured_action)
            || intent.required_capability != rule.required_capability
            || intent.risk > rule.maximum_risk
            || !principal.capabilities.contains(&rule.required_capability)
            || !principal.capabilities.contains(&action_capability)
            || !principal.purposes.contains(expected_operation)
            || !principal.processors.contains(&intent.connector)
            || !approval_allowed
            || missing_required_approval
            || missing_persisted_approval
            || !principal.residency_allowed
            || !principal.egress_allowed
        {
            return Ok(EvaluatedEffectAuthority::denied());
        }
        let effect_approved = match action {
            EffectPolicyAction::Prepare | EffectPolicyAction::Read => false,
            EffectPolicyAction::Authorize => {
                intent.risk == RiskLevel::Low || approval_kind.is_some()
            }
            EffectPolicyAction::Dispatch if require_persisted_approval => {
                intent.risk == RiskLevel::Low || approval_kind.is_some()
            }
            EffectPolicyAction::Dispatch
            | EffectPolicyAction::Reconcile
            | EffectPolicyAction::Compensate => true,
        };
        let digest = authority_digest(
            b"effect",
            [
                identity.tenant_id.as_str(),
                identity.principal_id.as_str(),
                expected_operation,
                intent.effect_id.as_str(),
                intent.connector.as_str(),
                intent.operation.as_str(),
                intent.target.as_str(),
                intent.arguments_digest.as_str(),
            ],
        )
        .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        let request = self
            .policy_request(
                PolicyResource::Effect,
                digest,
                identity,
                principal,
                None,
                expected_operation.to_owned(),
                Some(intent.connector.clone()),
                Some(action_capability),
                now,
                state.decision_ttl_seconds,
                Some(snapshot.policy_digest),
                Some(intent.risk),
                effect_approved,
                true,
            )
            .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        let decision = self
            .policy
            .authorize_effect(&request)
            .map_err(|_error| EffectPolicyFailure::Unavailable)?;
        let allowed = decision.outcome == PolicyOutcome::Allow
            || (action == EffectPolicyAction::Prepare
                && decision.outcome == PolicyOutcome::RequireApproval);
        Ok(EvaluatedEffectAuthority {
            policy_allows: allowed,
            capabilities: if allowed {
                principal.capabilities.clone()
            } else {
                BTreeSet::new()
            },
        })
    }
}

impl DomainIdentityResolver for ProductionDomainAuthority {
    fn resolve(
        &self,
        context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, DomainIdentityError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| DomainIdentityError::new(DomainIdentityErrorCode::Unavailable))?;
        context
            .check_active(now)
            .map_err(|_error| DomainIdentityError::new(DomainIdentityErrorCode::Cancelled))?;
        self.resolve_authenticated(context.identity())
            .map_err(|_error| DomainIdentityError::new(DomainIdentityErrorCode::Unavailable))?
            .ok_or_else(|| DomainIdentityError::new(DomainIdentityErrorCode::InvalidMapping))
    }
}

impl CatalogContextAuthorizer for ProductionDomainAuthority {
    fn authorize_catalog(
        &self,
        identity: &ResolvedDomainIdentity,
        observed_at: UtcTimestamp,
    ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
        let state = self
            .state()
            .map_err(|_error| CatalogContextAuthorizationError::Unavailable)?;
        let (_tenant, principal) = self
            .principal(&state, identity, observed_at)
            .map_err(map_catalog_lookup)?;
        self.catalog_authorization(
            identity,
            principal.project_ids.clone(),
            principal.catalog_purpose.clone(),
            principal.catalog_processor.clone(),
            Capability::ReadContext,
            observed_at,
            false,
        )
    }

    fn authorize_contract(
        &self,
        identity: &ResolvedDomainIdentity,
        contract: &ContextContract,
        observed_at: UtcTimestamp,
    ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
        let requested_projects: BTreeSet<_> = contract.project_ids.iter().cloned().collect();
        if contract.principal_id != identity.principal_id
            || requested_projects.len() != contract.project_ids.len()
        {
            return Err(CatalogContextAuthorizationError::InvalidDecision);
        }
        self.catalog_authorization(
            identity,
            requested_projects,
            contract.purpose.clone(),
            contract.target.provider.clone(),
            Capability::CompileContext,
            observed_at,
            true,
        )
    }
}

impl SpaceHandoffAuthorizer for ProductionDomainAuthority {
    fn authorize(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        now: UtcTimestamp,
    ) -> Result<CurrentSpaceHandoffAuthorization, DomainAuthorizationError> {
        self.current_space_authorization(context, identity, scope, now)
    }

    fn reference_authorized(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        scope: &SpaceHandoffAuthorizationScope,
        policy_digest: &ContentDigest,
        version_id: &VersionId,
        now: UtcTimestamp,
    ) -> Result<bool, DomainAuthorizationError> {
        let current = self.current_space_authorization(context, identity, scope, now)?;
        let snapshot = self.snapshot().map_err(map_domain_policy_failure)?;
        if current.policy_digest != *policy_digest || snapshot.policy_digest != *policy_digest {
            return Ok(false);
        }
        let state = self
            .state()
            .map_err(|_error| DomainAuthorizationError::Unavailable)?;
        let (_tenant, principal) = self
            .principal(&state, identity, now)
            .map_err(map_domain_lookup)?;
        let digest = authority_digest(
            b"handoff-reference",
            [
                identity.tenant_id.as_str(),
                identity.principal_id.as_str(),
                context.operation().as_str(),
                version_id.as_str(),
            ],
        )
        .map_err(|_error| DomainAuthorizationError::Invalid)?;
        let request = self
            .policy_request(
                PolicyResource::Bundle,
                digest,
                identity,
                principal,
                None,
                context.operation().as_str().to_owned(),
                None,
                Some(Capability::ReadContext),
                now,
                state.decision_ttl_seconds,
                Some(policy_digest.clone()),
                None,
                false,
                true,
            )
            .map_err(map_domain_lookup)?;
        match self.policy.authorize_bundle(&request) {
            Ok(decision) => Ok(decision.outcome == PolicyOutcome::Allow),
            Err(error) => Err(map_domain_policy_failure(error)),
        }
    }
}

impl EffectPolicyEvaluator for ProductionDomainAuthority {
    fn evaluate(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        action: EffectPolicyAction,
        intent: &EffectIntent,
        approval_kind: Option<ApprovalKind>,
    ) -> Result<EffectPolicyDecision, EffectPolicyFailure> {
        self.evaluate_effect_inner(context, identity, action, intent, approval_kind)
    }
}

impl EffectWorkerAuthority for ProductionDomainAuthority {
    fn authorize(
        &self,
        tenant_id: &RecordId,
        action: EffectWorkerAction,
        record: &DurableEffectRecord,
        now: UtcTimestamp,
    ) -> Result<EffectAuthorization, EffectWorkerAuthorityError> {
        let actor_id = record
            .journal
            .last()
            .map(|event| event.actor_id.clone())
            .ok_or(EffectWorkerAuthorityError)?;
        let identity = ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: actor_id.clone(),
        };
        let (policy_action, approval_kind, approval_valid) = match action {
            EffectWorkerAction::Dispatch => (
                EffectPolicyAction::Dispatch,
                record.approval.as_ref().map(|approval| approval.kind),
                record.approval.as_ref().is_none_or(|approval| {
                    approval.effect_id == record.intent.effect_id
                        && approval.bundle_id == record.intent.bundle_id
                        && approval.risk == record.intent.risk
                        && approval.approved_at <= now
                        && now < approval.expires_at
                }),
            ),
            EffectWorkerAction::Reconcile => (EffectPolicyAction::Reconcile, None, true),
        };
        if !approval_valid {
            return Ok(denied_effect_authorization(actor_id, now));
        }
        let decision = self
            .evaluate_effect_at(
                &identity,
                policy_action,
                &record.intent,
                approval_kind,
                effect_action_operation(policy_action),
                now,
                action == EffectWorkerAction::Dispatch,
                None,
            )
            .map_err(|_error| EffectWorkerAuthorityError)?;
        Ok(EffectAuthorization {
            actor_id,
            capabilities: if decision.policy_allows {
                decision.capabilities
            } else {
                BTreeSet::new()
            },
            policy_allows: decision.policy_allows,
            now,
        })
    }
}

impl HandoffResultMergePlanner for ProductionDomainAuthority {
    fn plan_mappings(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        authorization: &CurrentSpaceHandoffAuthorization,
        material: &HandoffMergeMaterial,
    ) -> Result<Vec<ResultMergeMapping>, SpaceHandoffDependencyError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
        let state = self
            .state()
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
        if !authenticated_mapping_matches(&state, context.identity(), identity) {
            return Err(SpaceHandoffDependencyError::Denied);
        }
        let snapshot = self
            .snapshot()
            .map_err(|_error| SpaceHandoffDependencyError::Unavailable)?;
        let (_tenant, principal) = self
            .principal(&state, identity, now)
            .map_err(map_merge_lookup)?;
        let target_project = authorization
            .resource_project_id
            .as_ref()
            .ok_or(SpaceHandoffDependencyError::Denied)?;
        if context.operation().as_str() != "mergeHandoff"
            || authorization.policy_digest != snapshot.policy_digest
            || authorization.effective.tenant != identity.tenant_id.as_str()
            || authorization.effective.subject_id != identity.principal_id
            || !authorization
                .effective
                .capabilities
                .contains(&Capability::PublishOverlay)
            || !principal.capabilities.contains(&Capability::PublishOverlay)
            || material.capsule.issuer_id != identity.principal_id
            || material.capsule.handoff_id != material.acceptance.handoff_id
            || material.capsule.handoff_id != material.result.delta.handoff_id
            || material.acceptance.recipient_id != material.result.delta.producer_id
            || material.acceptance_authority.compilation.bundle_id != material.acceptance.bundle_id
            || material.acceptance_authority.compilation.source_bundle_id
                != material.capsule.bundle_id
            || material
                .acceptance_authority
                .accepted
                .project_ids
                .binary_search(target_project)
                .is_err()
            || material
                .capsule
                .project_ids
                .iter()
                .any(|project| !principal.project_ids.contains(project))
        {
            return Err(SpaceHandoffDependencyError::Denied);
        }
        let mut versions = BTreeMap::new();
        for (values, kind) in [
            (&material.result.delta.decisions, ResultMergeKind::Decision),
            (&material.result.delta.artifacts, ResultMergeKind::Artifact),
            (
                &material.result.delta.source_changes,
                ResultMergeKind::SourceChange,
            ),
        ] {
            for version in values {
                if versions.insert(version.clone(), kind).is_some() {
                    return Err(SpaceHandoffDependencyError::Invalid);
                }
            }
        }
        versions
            .into_iter()
            .map(|(version_id, kind)| {
                let resource_key = ResourceKey::new(format!(
                    "handoff:{}:result:{}",
                    material.capsule.handoff_id.as_str(),
                    version_id.as_str()
                ))
                .map_err(|_error| SpaceHandoffDependencyError::Invalid)?;
                Ok(ResultMergeMapping {
                    version_id,
                    kind,
                    resource_key,
                })
            })
            .collect()
    }
}

impl DurableSnapshotAuthenticator for ProductionDomainAuthority {
    fn sign_snapshot_root(
        &self,
        tenant_id: &RecordId,
        payload_digest: [u8; 32],
    ) -> Result<SnapshotRootAuthentication, DurableSnapshotError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable))?;
        let state = self
            .state()
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable))?;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or_else(|| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))?;
        if !tenant.active || tenant.revoked_key_refs.contains(&tenant.issuer_key_ref) {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        let envelope = self
            .keys
            .sign(SignatureRequest {
                key_ref: &tenant.issuer_key_ref,
                tenant: tenant_id.as_str(),
                signer: SNAPSHOT_ROOT_SIGNER,
                purpose: SNAPSHOT_ROOT_SIGNATURE_PURPOSE,
                payload_digest,
                signed_at: now.unix_nanos(),
                expires_at: None,
            })
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable))?;
        Ok(SnapshotRootAuthentication {
            key_ref: envelope.key_ref,
            signed_at: envelope.signed_at,
            signature: envelope.signature.to_vec(),
        })
    }

    fn verify_snapshot_root(
        &self,
        tenant_id: &RecordId,
        payload_digest: &[u8; 32],
        authentication: &SnapshotRootAuthentication,
    ) -> Result<(), DurableSnapshotError> {
        let signature: [u8; 64] =
            authentication
                .signature
                .as_slice()
                .try_into()
                .map_err(|_error| {
                    DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot)
                })?;
        let now = self
            .clock
            .now()
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable))?;
        let state = self
            .state()
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::Unavailable))?;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or_else(|| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))?;
        if !tenant.active || tenant.revoked_key_refs.contains(&authentication.key_ref) {
            return Err(DurableSnapshotError::new(
                DurableSnapshotErrorCode::InvalidSnapshot,
            ));
        }
        let envelope = SignatureEnvelope {
            algorithm: KeyAlgorithm::Ed25519,
            key_ref: authentication.key_ref.clone(),
            signer: SNAPSHOT_ROOT_SIGNER.to_owned(),
            purpose: SNAPSHOT_ROOT_SIGNATURE_PURPOSE.to_owned(),
            signed_at: authentication.signed_at,
            expires_at: None,
            payload_digest: *payload_digest,
            signature,
        };
        self.keys
            .verify(
                &envelope,
                SignatureVerification {
                    tenant: tenant_id.as_str(),
                    signer: SNAPSHOT_ROOT_SIGNER,
                    purpose: SNAPSHOT_ROOT_SIGNATURE_PURPOSE,
                    payload_digest,
                    now: now.unix_nanos(),
                },
            )
            .map_err(|_error| DurableSnapshotError::new(DurableSnapshotErrorCode::InvalidSnapshot))
    }
}

impl EffectRecordSignatureAuthority for ProductionDomainAuthority {
    fn sign_effect_record(
        &self,
        tenant_id: &RecordId,
        payload_digest: [u8; 32],
    ) -> Result<EffectRecordSignature, EffectError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let state = self
            .state()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or_else(|| EffectError::new(EffectErrorCode::Unauthorized))?;
        if !tenant.active || tenant.revoked_key_refs.contains(&tenant.issuer_key_ref) {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        let envelope = self
            .keys
            .sign(SignatureRequest {
                key_ref: &tenant.issuer_key_ref,
                tenant: tenant_id.as_str(),
                signer: EFFECT_RECORD_SIGNER,
                purpose: EFFECT_RECORD_SIGNATURE_PURPOSE,
                payload_digest,
                signed_at: now.unix_nanos(),
                expires_at: None,
            })
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        Ok(EffectRecordSignature::new(
            envelope.key_ref,
            envelope.signed_at,
            envelope.signature,
        ))
    }

    fn verify_effect_record(
        &self,
        tenant_id: &RecordId,
        payload_digest: &[u8; 32],
        signature: &EffectRecordSignature,
    ) -> Result<(), EffectError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let state = self
            .state()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or_else(|| EffectError::new(EffectErrorCode::CorruptJournal))?;
        if !tenant.active || tenant.revoked_key_refs.contains(signature.key_ref()) {
            return Err(EffectError::new(EffectErrorCode::CorruptJournal));
        }
        let envelope = SignatureEnvelope {
            algorithm: KeyAlgorithm::Ed25519,
            key_ref: signature.key_ref().clone(),
            signer: EFFECT_RECORD_SIGNER.to_owned(),
            purpose: EFFECT_RECORD_SIGNATURE_PURPOSE.to_owned(),
            signed_at: signature.signed_at_unix_nanos(),
            expires_at: None,
            payload_digest: *payload_digest,
            signature: *signature.signature(),
        };
        self.keys
            .verify(
                &envelope,
                SignatureVerification {
                    tenant: tenant_id.as_str(),
                    signer: EFFECT_RECORD_SIGNER,
                    purpose: EFFECT_RECORD_SIGNATURE_PURPOSE,
                    payload_digest,
                    now: now.unix_nanos(),
                },
            )
            .map_err(|_error| EffectError::new(EffectErrorCode::CorruptJournal))
    }
}

impl ProductionTenantProvider for ProductionDomainAuthority {
    fn active_tenants(&self) -> Result<Vec<RecordId>, LifecycleError> {
        let state = self
            .state()
            .map_err(|_error| LifecycleError::action_failed())?;
        Ok(state
            .tenants
            .values()
            .filter(|tenant| tenant.active)
            .map(|tenant| tenant.tenant_id.clone())
            .collect())
    }
}

impl OperatorAuthorizer for ProductionDomainAuthority {
    fn is_operator(&self, identity: &AuthenticatedIdentity) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        let Ok(state) = self.state() else {
            return false;
        };
        let Some(tenant_id) = state.tenant_by_transport.get(identity.tenant().as_str()) else {
            return false;
        };
        let Some(tenant) = state.tenants.get(tenant_id) else {
            return false;
        };
        let Some(principal_id) = tenant
            .principal_by_transport
            .get(identity.principal().as_str())
        else {
            return false;
        };
        let Some(principal) = tenant.principals.get(principal_id) else {
            return false;
        };
        let resolved = ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
        };
        if !principal.operator
            || self.principal(&state, &resolved, now).is_err()
            || self.snapshot().is_err()
        {
            return false;
        }
        let Ok(digest) = authority_digest(
            b"operator",
            [
                tenant_id.as_str(),
                principal_id.as_str(),
                identity.tenant().as_str(),
                identity.principal().as_str(),
            ],
        ) else {
            return false;
        };
        let Ok(request) = self.policy_request(
            PolicyResource::Partition,
            digest,
            &resolved,
            principal,
            None,
            principal.catalog_purpose.clone(),
            Some(principal.catalog_processor.clone()),
            None,
            now,
            state.decision_ttl_seconds,
            None,
            None,
            false,
            true,
        ) else {
            return false;
        };
        self.policy
            .authorize_partition(&request)
            .is_ok_and(|decision| decision.outcome == PolicyOutcome::Allow)
    }
}

impl fmt::Debug for ProductionDomainAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenant_count = self.state.read().map_or(0, |state| state.tenants.len());
        formatter
            .debug_struct("ProductionDomainAuthority")
            .field("tenant_count", &tenant_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityLookupError {
    Invalid,
    Denied,
}

fn require_protected_snapshot(
    policy: &CompiledPolicyEngine,
) -> Result<PolicySnapshot, ProductionAuthorityError> {
    let snapshot = policy.snapshot().map_err(|_error| {
        ProductionAuthorityError::new(ProductionAuthorityErrorCode::PolicyUnavailable)
    })?;
    if !snapshot.protected {
        return Err(invalid_configuration());
    }
    Ok(snapshot)
}

fn validate_configuration(
    configuration: ProductionAuthorityConfiguration,
    keys: &dyn KeyProvider,
    now: UtcTimestamp,
) -> Result<AuthorityState, ProductionAuthorityError> {
    if configuration.schema_version != AUTHORITY_SCHEMA
        || !valid_exact_text(&configuration.runtime_audience)
        || configuration.decision_ttl_seconds == 0
        || configuration.decision_ttl_seconds > MAX_DECISION_TTL_SECONDS
        || configuration.tenants.is_empty()
    {
        return Err(invalid_configuration());
    }
    if configuration.tenants.len() > MAX_TENANTS {
        return Err(limit_exceeded());
    }
    let mut tenants = BTreeMap::new();
    let mut tenant_by_transport = BTreeMap::new();
    let mut all_project_ids = BTreeSet::new();
    let mut all_principal_ids = BTreeSet::new();
    let mut all_grant_ids = BTreeSet::new();
    for tenant in configuration.tenants {
        if TenantId::new(tenant.authenticated_tenant.clone()).is_err()
            || tenant.project_ids.is_empty()
            || tenant.principals.is_empty()
        {
            return Err(invalid_configuration());
        }
        if tenant.project_ids.len() > MAX_PROJECTS_PER_TENANT
            || tenant.principals.len() > MAX_PRINCIPALS_PER_TENANT
            || tenant.revoked_principal_ids.len() > MAX_PRINCIPALS_PER_TENANT
            || tenant.revoked_key_refs.len() > MAX_REVOKED_KEYS_PER_TENANT
        {
            return Err(limit_exceeded());
        }
        let project_ids = unique_set(tenant.project_ids)?;
        if project_ids
            .iter()
            .any(|project_id| !all_project_ids.insert(project_id.clone()))
        {
            return Err(invalid_configuration());
        }
        let revoked_principal_ids = unique_set(tenant.revoked_principal_ids)?;
        let revoked_key_refs = unique_set(tenant.revoked_key_refs)?;
        if revoked_key_refs.contains(&tenant.issuer_key_ref) {
            return Err(invalid_configuration());
        }
        let metadata = keys
            .resolve(
                &tenant.issuer_key_ref,
                tenant.tenant_id.as_str(),
                KeyPurpose::Signing,
                now.unix_nanos(),
            )
            .map_err(|_error| {
                ProductionAuthorityError::new(ProductionAuthorityErrorCode::KeyUnavailable)
            })?;
        if metadata.status != KeyStatus::Active
            || metadata.tenant != tenant.tenant_id.as_str()
            || metadata.key_ref != tenant.issuer_key_ref
            || metadata.purpose != KeyPurpose::Signing
            || metadata.algorithm != KeyAlgorithm::Ed25519
            || metadata.public_identity.is_none()
        {
            return Err(ProductionAuthorityError::new(
                ProductionAuthorityErrorCode::KeyUnavailable,
            ));
        }
        let mut principals = BTreeMap::new();
        let mut principal_by_transport = BTreeMap::new();
        for principal in tenant.principals {
            let compiled = validate_principal(principal, &project_ids, now)?;
            if !all_principal_ids.insert(compiled.principal_id.clone())
                || !all_grant_ids.insert(compiled.grant_id.clone())
                || principal_by_transport
                    .insert(
                        compiled.authenticated_principal.clone(),
                        compiled.principal_id.clone(),
                    )
                    .is_some()
                || principals
                    .insert(compiled.principal_id.clone(), compiled)
                    .is_some()
            {
                return Err(invalid_configuration());
            }
        }
        let tenant_id = tenant.tenant_id;
        let compiled = TenantGrant {
            tenant_id: tenant_id.clone(),
            active: tenant.active,
            issuer_key_ref: tenant.issuer_key_ref,
            project_ids,
            principals,
            principal_by_transport,
            revoked_principal_ids,
            revoked_key_refs,
        };
        if tenant_by_transport
            .insert(tenant.authenticated_tenant, tenant_id.clone())
            .is_some()
            || tenants.insert(tenant_id, compiled).is_some()
        {
            return Err(invalid_configuration());
        }
    }
    Ok(AuthorityState {
        runtime_audience: configuration.runtime_audience,
        decision_ttl_seconds: configuration.decision_ttl_seconds,
        tenants,
        tenant_by_transport,
    })
}

fn validate_principal(
    principal: ProductionPrincipalAuthority,
    tenant_projects: &BTreeSet<RecordId>,
    now: UtcTimestamp,
) -> Result<PrincipalGrant, ProductionAuthorityError> {
    if PrincipalId::new(principal.authenticated_principal.clone()).is_err()
        || principal.not_before >= principal.expires_at
        || (principal.active && principal.expires_at <= now)
        || principal.project_ids.is_empty()
        || principal.capabilities.is_empty()
        || principal.purposes.is_empty()
        || principal.processors.is_empty()
        || !valid_exact_text(&principal.catalog_purpose)
        || !valid_exact_text(&principal.catalog_processor)
    {
        return Err(invalid_configuration());
    }
    if principal.roles.len() > MAX_ROLES_PER_PRINCIPAL
        || principal.project_ids.len() > MAX_PROJECTS_PER_PRINCIPAL
        || principal.purposes.len() > MAX_PURPOSES_PER_PRINCIPAL
        || principal.processors.len() > MAX_PROCESSORS_PER_PRINCIPAL
        || principal.effect_rules.len() > MAX_EFFECT_RULES_PER_PRINCIPAL
    {
        return Err(limit_exceeded());
    }
    let roles = unique_text_set(principal.roles)?;
    let project_ids = unique_set(principal.project_ids)?;
    let capabilities = unique_set(principal.capabilities)?;
    let delegatable_capabilities = unique_set(principal.delegatable_capabilities)?;
    let purposes = unique_text_set(principal.purposes)?;
    let processors = unique_text_set(principal.processors)?;
    if !project_ids.is_subset(tenant_projects)
        || !delegatable_capabilities.is_subset(&capabilities)
        || !purposes.contains(&principal.catalog_purpose)
        || !processors.contains(&principal.catalog_processor)
    {
        return Err(invalid_configuration());
    }
    let mut effect_rules = BTreeMap::new();
    for rule in principal.effect_rules {
        if !valid_exact_text(&rule.connector)
            || !valid_exact_text(&rule.operation)
            || !valid_exact_text(&rule.target)
            || rule.allowed_actions.is_empty()
            || !processors.contains(&rule.connector)
            || !capabilities.contains(&rule.required_capability)
        {
            return Err(invalid_configuration());
        }
        let key = (rule.connector, rule.operation, rule.target);
        let compiled = EffectRule {
            required_capability: rule.required_capability,
            maximum_risk: rule.maximum_risk,
            allowed_actions: unique_set(rule.allowed_actions)?,
            allowed_approval_kinds: unique_set(rule.allowed_approval_kinds)?,
        };
        if effect_rules.insert(key, compiled).is_some() {
            return Err(invalid_configuration());
        }
    }
    Ok(PrincipalGrant {
        authenticated_principal: principal.authenticated_principal,
        principal_id: principal.principal_id,
        grant_id: principal.grant_id,
        active: principal.active,
        operator: principal.operator,
        not_before: principal.not_before,
        expires_at: principal.expires_at,
        roles,
        project_ids,
        capabilities,
        delegatable_capabilities,
        purposes,
        processors,
        catalog_purpose: principal.catalog_purpose,
        catalog_processor: principal.catalog_processor,
        maximum_classification: principal.maximum_classification,
        maximum_instruction_authority: principal.maximum_instruction_authority,
        residency_allowed: principal.residency_allowed,
        egress_allowed: principal.egress_allowed,
        vector_allowed: principal.vector_allowed,
        handoff_target_allowed: principal.handoff_target_allowed,
        effect_rules,
    })
}

fn unique_set<T: Ord>(values: Vec<T>) -> Result<BTreeSet<T>, ProductionAuthorityError> {
    let length = values.len();
    let set: BTreeSet<_> = values.into_iter().collect();
    if set.len() == length {
        Ok(set)
    } else {
        Err(invalid_configuration())
    }
}

fn unique_text_set(values: Vec<String>) -> Result<BTreeSet<String>, ProductionAuthorityError> {
    if values.iter().any(|value| !valid_exact_text(value)) {
        return Err(invalid_configuration());
    }
    unique_set(values)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_exact_text(value: &str) -> bool {
    valid_text(value) && value != "*"
}

fn authenticated_mapping_matches(
    state: &AuthorityState,
    authenticated: &AuthenticatedIdentity,
    resolved: &ResolvedDomainIdentity,
) -> bool {
    state
        .tenant_by_transport
        .get(authenticated.tenant().as_str())
        .is_some_and(|tenant_id| tenant_id == &resolved.tenant_id)
        && state
            .tenants
            .get(&resolved.tenant_id)
            .and_then(|tenant| {
                tenant
                    .principal_by_transport
                    .get(authenticated.principal().as_str())
            })
            .is_some_and(|principal_id| principal_id == &resolved.principal_id)
}

fn invalid_configuration() -> ProductionAuthorityError {
    ProductionAuthorityError::new(ProductionAuthorityErrorCode::InvalidConfiguration)
}

fn limit_exceeded() -> ProductionAuthorityError {
    ProductionAuthorityError::new(ProductionAuthorityErrorCode::LimitExceeded)
}

fn add_seconds(now: UtcTimestamp, seconds: u32) -> Result<UtcTimestamp, AuthorityLookupError> {
    let nanos = i128::from(seconds)
        .checked_mul(1_000_000_000)
        .and_then(|delta| now.unix_nanos().checked_add(delta))
        .ok_or(AuthorityLookupError::Invalid)?;
    UtcTimestamp::from_unix_nanos(nanos).map_err(|_error| AuthorityLookupError::Invalid)
}

fn authority_digest<'a>(
    domain: &[u8],
    values: impl IntoIterator<Item = &'a str>,
) -> Result<ContentDigest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PRODUCTION-AUTHORITY\0v1\0");
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_error| ())?
            .to_be_bytes(),
    );
    hasher.update(domain);
    for value in values {
        hasher.update(
            u64::try_from(value.len())
                .map_err(|_error| ())?
                .to_be_bytes(),
        );
        hasher.update(value.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut text = String::from("1220");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").map_err(|_error| ())?;
    }
    ContentDigest::new(text).map_err(|_error| ())
}

fn space_scope_digest(
    identity: &ResolvedDomainIdentity,
    operation: &str,
    scope: &SpaceHandoffAuthorizationScope,
) -> Result<ContentDigest, ()> {
    let (kind, first, second, project) = match scope {
        SpaceHandoffAuthorizationScope::NewSpace { project_id } => {
            ("new-space", project_id.as_str(), "", project_id.as_str())
        }
        SpaceHandoffAuthorizationScope::Space {
            space_id,
            project_id,
        } => ("space", space_id.as_str(), "", project_id.as_str()),
        SpaceHandoffAuthorizationScope::NewHandoff => ("new-handoff", "", "", ""),
        SpaceHandoffAuthorizationScope::Handoff { handoff_id } => {
            ("handoff", handoff_id.as_str(), "", "")
        }
        SpaceHandoffAuthorizationScope::HandoffMerge {
            handoff_id,
            space_id,
            project_id,
        } => (
            "handoff-merge",
            handoff_id.as_str(),
            space_id.as_str(),
            project_id.as_str(),
        ),
    };
    authority_digest(
        b"space-handoff",
        [
            identity.tenant_id.as_str(),
            identity.principal_id.as_str(),
            operation,
            kind,
            first,
            second,
            project,
        ],
    )
}

fn effect_action_capability(action: EffectPolicyAction) -> Capability {
    match action {
        EffectPolicyAction::Prepare | EffectPolicyAction::Read => Capability::ProposeEffect,
        EffectPolicyAction::Authorize
        | EffectPolicyAction::Dispatch
        | EffectPolicyAction::Compensate => Capability::ApproveEffect,
        EffectPolicyAction::Reconcile => Capability::ReconcileEffect,
    }
}

fn effect_action_operation(action: EffectPolicyAction) -> &'static str {
    match action {
        EffectPolicyAction::Prepare => "prepareEffect",
        EffectPolicyAction::Authorize => "authorizeEffect",
        EffectPolicyAction::Dispatch => "dispatchEffect",
        EffectPolicyAction::Read => "getEffectStatus",
        EffectPolicyAction::Reconcile => "reconcileEffect",
        EffectPolicyAction::Compensate => "compensateEffect",
    }
}

fn denied_effect_authorization(actor_id: RecordId, now: UtcTimestamp) -> EffectAuthorization {
    EffectAuthorization {
        actor_id,
        capabilities: BTreeSet::new(),
        policy_allows: false,
        now,
    }
}

fn require_allow(
    result: Result<PolicyDecision, PolicyError>,
) -> Result<PolicyDecision, DecisionError> {
    match result {
        Ok(decision) if decision.outcome == PolicyOutcome::Allow => Ok(decision),
        Ok(_decision) => Err(DecisionError::Denied),
        Err(error) => Err(DecisionError::Policy(error)),
    }
}

enum DecisionError {
    Denied,
    Policy(PolicyError),
}

fn map_catalog_lookup(error: AuthorityLookupError) -> CatalogContextAuthorizationError {
    match error {
        AuthorityLookupError::Denied => CatalogContextAuthorizationError::Denied,
        AuthorityLookupError::Invalid => CatalogContextAuthorizationError::InvalidDecision,
    }
}

fn map_catalog_policy_failure(error: PolicyError) -> CatalogContextAuthorizationError {
    match error.code() {
        PolicyErrorCode::Unavailable => CatalogContextAuthorizationError::Unavailable,
        _ => CatalogContextAuthorizationError::InvalidDecision,
    }
}

fn map_catalog_decision(error: DecisionError) -> CatalogContextAuthorizationError {
    match error {
        DecisionError::Denied => CatalogContextAuthorizationError::Denied,
        DecisionError::Policy(error) => map_catalog_policy_failure(error),
    }
}

fn map_domain_lookup(error: AuthorityLookupError) -> DomainAuthorizationError {
    match error {
        AuthorityLookupError::Denied => DomainAuthorizationError::Denied,
        AuthorityLookupError::Invalid => DomainAuthorizationError::Invalid,
    }
}

fn map_domain_policy_failure(error: PolicyError) -> DomainAuthorizationError {
    match error.code() {
        PolicyErrorCode::Unavailable => DomainAuthorizationError::Unavailable,
        _ => DomainAuthorizationError::Invalid,
    }
}

fn map_domain_decision(error: DecisionError) -> DomainAuthorizationError {
    match error {
        DecisionError::Denied => DomainAuthorizationError::Denied,
        DecisionError::Policy(error) => map_domain_policy_failure(error),
    }
}

fn map_merge_lookup(error: AuthorityLookupError) -> SpaceHandoffDependencyError {
    match error {
        AuthorityLookupError::Denied => SpaceHandoffDependencyError::Denied,
        AuthorityLookupError::Invalid => SpaceHandoffDependencyError::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityError, DomainIdentityErrorCode};
    use cigar_api::{CancellationToken, OperationId, PrincipalId, TenantId, TraceId};
    use cigar_crypto::{CreateKeyRequest, MemoryKeyProvider};
    use cigar_policy::{PolicyProfile, PolicyRule};
    use cigar_protocol::{
        BlobRef, Budget, ConsistencyMode, ContextSpaceId, CoordinationEvent, CoordinationEventKind,
        EffectJournalEvent, EffectState, ExtensionMap, HandoffAcceptance, HandoffCapsule,
        HandoffDelta, HandoffReferences, IdempotencyKey, LaneKind, MediaType, OperationClass,
        RecipientSelector, RetryPolicy, SchemaVersion, TargetProfile,
    };
    use cigar_space::{
        AcceptedHandoffContext, HandoffAcceptanceAuthority, HandoffResultReceipt,
        RecipientBundleReceipt,
    };
    use std::error::Error;
    use std::sync::Mutex;

    type TestResult<T> = Result<T, Box<dyn Error>>;

    fn failure<T, E>(result: Result<T, E>) -> TestResult<E> {
        match result {
            Ok(_value) => Err("expected operation to fail".into()),
            Err(error) => Ok(error),
        }
    }

    fn tenant(
        configuration: &ProductionAuthorityConfiguration,
    ) -> TestResult<&ProductionTenantAuthority> {
        match configuration.tenants.first() {
            Some(tenant) => Ok(tenant),
            None => Err("missing test tenant".into()),
        }
    }

    fn tenant_mut(
        configuration: &mut ProductionAuthorityConfiguration,
    ) -> TestResult<&mut ProductionTenantAuthority> {
        match configuration.tenants.first_mut() {
            Some(tenant) => Ok(tenant),
            None => Err("missing test tenant".into()),
        }
    }

    fn principal_mut(
        configuration: &mut ProductionAuthorityConfiguration,
    ) -> TestResult<&mut ProductionPrincipalAuthority> {
        match tenant_mut(configuration)?.principals.first_mut() {
            Some(principal) => Ok(principal),
            None => Err("missing test principal".into()),
        }
    }

    struct TestClock(Mutex<UtcTimestamp>);

    impl TestClock {
        fn new(now: UtcTimestamp) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: UtcTimestamp) -> TestResult<()> {
            *self
                .0
                .lock()
                .map_err(|_error| AuthorityError::InvalidClock)? = now;
            Ok(())
        }
    }

    impl AuthorityClock for TestClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            self.0
                .lock()
                .map(|now| *now)
                .map_err(|_error| AuthorityError::InvalidClock)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            let seconds = self.now()?.unix_nanos().div_euclid(1_000_000_000);
            i64::try_from(seconds).map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    struct Fixture {
        authority: Arc<ProductionDomainAuthority>,
        configuration: ProductionAuthorityConfiguration,
        policy: Arc<CompiledPolicyEngine>,
        keys: Arc<MemoryKeyProvider>,
        clock: Arc<TestClock>,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let clock = Arc::new(TestClock::new(time(100)?));
            let policy = Arc::new(CompiledPolicyEngine::default());
            policy.install(policy_profile(true, 1), time(1)?)?;
            let keys = Arc::new(MemoryKeyProvider::default());
            let issuer = keys.create(CreateKeyRequest {
                tenant: record(1)?.as_str().to_owned(),
                purpose: KeyPurpose::Signing,
                algorithm: KeyAlgorithm::Ed25519,
                created_at: time(1)?.unix_nanos(),
                activated_at: time(1)?.unix_nanos(),
            })?;
            let configuration = configuration(issuer.key_ref)?;
            let authority = Arc::new(ProductionDomainAuthority::new(
                configuration.clone(),
                policy.clone(),
                keys.clone(),
                clock.clone(),
            )?);
            Ok(Self {
                authority,
                configuration,
                policy,
                keys,
                clock,
            })
        }
    }

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(value: u64) -> TestResult<ContentDigest> {
        Ok(ContentDigest::new(format!("1220{value:064x}"))?)
    }

    fn version(value: u64) -> TestResult<VersionId> {
        Ok(VersionId::new(format!("1220{value:064x}"))?)
    }

    fn time(seconds: i64) -> TestResult<UtcTimestamp> {
        Ok(UtcTimestamp::from_unix_nanos(
            i128::from(seconds) * 1_000_000_000,
        )?)
    }

    fn policy_profile(protected: bool, revision: u64) -> PolicyProfile {
        PolicyProfile {
            schema_version: "cigar.policy-profile.v1".to_owned(),
            revision,
            protected,
            rules: Vec::<PolicyRule>::new(),
        }
    }

    fn capabilities() -> Vec<Capability> {
        vec![
            Capability::ReadContext,
            Capability::CompileContext,
            Capability::WriteOverlay,
            Capability::PublishOverlay,
            Capability::CreateHandoff,
            Capability::AcceptHandoff,
            Capability::InvokeTool,
            Capability::ProposeEffect,
            Capability::ApproveEffect,
            Capability::ReconcileEffect,
        ]
    }

    fn purposes() -> Vec<String> {
        [
            "catalog.read",
            "coding",
            "createSpace",
            "forkSpace",
            "publishSpace",
            "getSpaceLog",
            "subscribeSpaceEvents",
            "createSpaceCheckpoint",
            "listSpaceConflicts",
            "resolveSpaceConflict",
            "createHandoff",
            "previewHandoff",
            "acceptHandoff",
            "revokeHandoff",
            "recordHandoffResult",
            "mergeHandoff",
            "prepareEffect",
            "authorizeEffect",
            "dispatchEffect",
            "getEffectStatus",
            "reconcileEffect",
            "compensateEffect",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn configuration(key_ref: KeyRef) -> TestResult<ProductionAuthorityConfiguration> {
        Ok(ProductionAuthorityConfiguration {
            schema_version: AUTHORITY_SCHEMA.to_owned(),
            runtime_audience: "runtime-v1".to_owned(),
            decision_ttl_seconds: 60,
            tenants: vec![ProductionTenantAuthority {
                authenticated_tenant: "transport-tenant".to_owned(),
                tenant_id: record(1)?,
                active: true,
                issuer_key_ref: key_ref,
                project_ids: vec![record(2)?],
                principals: vec![ProductionPrincipalAuthority {
                    authenticated_principal: "transport-principal".to_owned(),
                    principal_id: record(3)?,
                    grant_id: record(4)?,
                    active: true,
                    operator: true,
                    not_before: time(10)?,
                    expires_at: time(1_000)?,
                    roles: vec!["developer".to_owned()],
                    project_ids: vec![record(2)?],
                    capabilities: capabilities(),
                    delegatable_capabilities: vec![
                        Capability::ReadContext,
                        Capability::WriteOverlay,
                        Capability::PublishOverlay,
                    ],
                    purposes: purposes(),
                    processors: vec!["local".to_owned(), "test.connector".to_owned()],
                    catalog_purpose: "catalog.read".to_owned(),
                    catalog_processor: "local".to_owned(),
                    maximum_classification: Classification::Restricted,
                    maximum_instruction_authority: InstructionAuthority::System,
                    residency_allowed: true,
                    egress_allowed: true,
                    vector_allowed: true,
                    handoff_target_allowed: true,
                    effect_rules: vec![ProductionEffectAuthorityRule {
                        connector: "test.connector".to_owned(),
                        operation: "send".to_owned(),
                        target: "target".to_owned(),
                        required_capability: Capability::InvokeTool,
                        maximum_risk: RiskLevel::Critical,
                        allowed_actions: vec![
                            ConfiguredEffectAction::Prepare,
                            ConfiguredEffectAction::Authorize,
                            ConfiguredEffectAction::Dispatch,
                            ConfiguredEffectAction::Read,
                            ConfiguredEffectAction::Reconcile,
                            ConfiguredEffectAction::Compensate,
                        ],
                        allowed_approval_kinds: vec![ApprovalKind::Human],
                    }],
                }],
                revoked_principal_ids: Vec::new(),
                revoked_key_refs: Vec::new(),
            }],
        })
    }

    fn authenticated(principal: &str) -> TestResult<AuthenticatedIdentity> {
        Ok(AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("transport-tenant")?,
            PrincipalId::new(principal)?,
        ))
    }

    fn resolved() -> TestResult<ResolvedDomainIdentity> {
        Ok(ResolvedDomainIdentity {
            tenant_id: record(1)?,
            principal_id: record(3)?,
        })
    }

    fn context(operation: &str, principal: &str) -> TestResult<RequestContext> {
        Ok(RequestContext::new(
            authenticated(principal)?,
            OperationId::new(operation)?,
            time(900)?,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            CancellationToken::new(),
            time(1)?,
        )?)
    }

    fn contract() -> TestResult<ContextContract> {
        Ok(ContextContract {
            schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
            job_goal: "compile exact context".to_owned(),
            operation_class: OperationClass::Read,
            principal_id: record(3)?,
            purpose: "coding".to_owned(),
            context_space_id: None,
            project_ids: vec![record(2)?],
            target: TargetProfile {
                provider: "local".to_owned(),
                model_family: "test".to_owned(),
                tokenizer_fingerprint: digest(20)?,
                materializer_fingerprint: digest(21)?,
                max_context_tokens: 4_096,
            },
            budget: budget(),
            requirements: Vec::new(),
            consistency: ConsistencyMode::Strong,
            maximum_staleness: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn budget() -> Budget {
        Budget {
            total_input_tokens: 1,
            output_reserve_tokens: 1,
            lane_input_tokens: [(LaneKind::Rules, 1)].into_iter().collect(),
        }
    }

    fn intent(risk: RiskLevel) -> TestResult<EffectIntent> {
        Ok(EffectIntent {
            schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
            effect_id: record(30)?,
            connector: "test.connector".to_owned(),
            operation: "send".to_owned(),
            arguments_digest: digest(31)?,
            encrypted_arguments: BlobRef {
                digest: digest(32)?,
                size_bytes: 12,
                media_type: MediaType::new("application/octet-stream")?,
            },
            target: "target".to_owned(),
            preconditions: Vec::new(),
            result_schema_digest: digest(33)?,
            risk,
            source_decision_id: version(34)?,
            bundle_id: version(35)?,
            required_capability: Capability::InvokeTool,
            idempotency_scope: "scope".to_owned(),
            idempotency_key: IdempotencyKey::new("key")?,
            retry_policy: RetryPolicy::Never,
            created_at: time(10)?,
            expires_at: time(900)?,
            compensation: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn effect_record(intent: EffectIntent, actor_id: RecordId) -> TestResult<DurableEffectRecord> {
        Ok(DurableEffectRecord {
            intent_digest: digest(40)?,
            state: EffectState::Dispatching,
            effect_version: 1,
            approval: None,
            approval_digest: None,
            attempts: Vec::new(),
            receipts: Vec::new(),
            reconciliations: Vec::new(),
            compensation_link: None,
            journal: vec![EffectJournalEvent {
                schema_version: SchemaVersion::new("cigar.effect-journal-event", 1)?,
                event_id: record(41)?,
                effect_id: intent.effect_id.clone(),
                sequence: 1,
                expected_effect_version: 0,
                from_state: EffectState::Authorized,
                to_state: EffectState::Dispatching,
                actor_id,
                payload_digest: digest(42)?,
                previous_event_digest: None,
                event_digest: digest(43)?,
                recorded_at: time(100)?,
            }],
            outbox: None,
            intent,
        })
    }

    fn merge_material(policy_digest: ContentDigest) -> TestResult<HandoffMergeMaterial> {
        let handoff_id = record(50)?;
        let recipient_id = record(51)?;
        let delta = HandoffDelta {
            schema_version: SchemaVersion::new("cigar.handoff-delta", 1)?,
            delta_id: record(52)?,
            handoff_id: handoff_id.clone(),
            base_commit_id: version(53)?,
            producer_id: recipient_id.clone(),
            claims: Vec::new(),
            decisions: vec![version(54)?],
            artifacts: vec![version(55)?],
            source_changes: vec![version(56)?],
            verifier_receipts: Vec::new(),
            unresolved_questions: Vec::new(),
            blockers: Vec::new(),
            effect_references: Vec::new(),
            requested_followup_capabilities: Vec::new(),
            extensions: ExtensionMap::default(),
        };
        let capsule = HandoffCapsule {
            schema_version: SchemaVersion::new("cigar.handoff", 1)?,
            handoff_id: handoff_id.clone(),
            issuer_id: record(3)?,
            recipient: RecipientSelector::Principal(recipient_id.clone()),
            task: "bounded delegated task".to_owned(),
            acceptance_criteria: vec!["return evidence".to_owned()],
            project_ids: vec![record(2)?],
            delegated_capabilities: vec![Capability::ReadContext],
            rejected_capabilities: Vec::new(),
            budget: budget(),
            topics: Vec::new(),
            references: HandoffReferences::default(),
            bundle_id: version(57)?,
            audience: "runtime-v1".to_owned(),
            created_at: time(10)?,
            expires_at: time(900)?,
            nonce: vec![1],
            reusable: false,
            issuer_key_id: "issuer".to_owned(),
            signature: vec![1],
            extensions: ExtensionMap::default(),
        };
        let acceptance = HandoffAcceptance {
            schema_version: SchemaVersion::new("cigar.handoff-acceptance", 1)?,
            acceptance_id: record(58)?,
            handoff_id: handoff_id.clone(),
            recipient_id,
            accepted_capabilities: vec![Capability::ReadContext],
            rejected_capabilities: Vec::new(),
            unavailable_references: Vec::new(),
            policy_digest,
            bundle_id: version(57)?,
            accepted_at: time(20)?,
            acknowledgement_digest: digest(59)?,
        };
        Ok(HandoffMergeMaterial {
            acceptance_authority: HandoffAcceptanceAuthority {
                accepted: AcceptedHandoffContext {
                    recipient_id: acceptance.recipient_id.clone(),
                    project_ids: capsule.project_ids.clone(),
                    capabilities: acceptance.accepted_capabilities.clone(),
                    references: capsule.references.clone(),
                    budget: capsule.budget.clone(),
                },
                compilation: RecipientBundleReceipt {
                    bundle_id: acceptance.bundle_id.clone(),
                    source_bundle_id: capsule.bundle_id.clone(),
                    target_plan_id: record(62)?,
                    target_plan_revision: 1,
                    target_plan_digest: digest(63)?,
                    derivation_digest: digest(64)?,
                },
            },
            capsule,
            acceptance,
            result: HandoffResultReceipt {
                acceptance_id: record(58)?,
                revision: 1,
                delta,
                event: CoordinationEvent {
                    event_id: record(60)?,
                    kind: CoordinationEventKind::AgentResultProposed,
                    payload_digest: digest(61)?,
                },
            },
        })
    }

    #[test]
    fn strict_configuration_rejects_ambiguity_wildcards_limits_and_bad_dependencies()
    -> TestResult<()> {
        let fixture = Fixture::new()?;
        let encoded = serde_json::to_vec(&fixture.configuration)?;
        assert_eq!(
            ProductionAuthorityConfiguration::from_json(&encoded)?,
            fixture.configuration
        );

        let duplicate = br#"{"schema_version":"cigar.production-authority.v1","schema_version":"cigar.production-authority.v1"}"#;
        assert_eq!(
            failure(ProductionAuthorityConfiguration::from_json(duplicate))?.code(),
            ProductionAuthorityErrorCode::InvalidConfiguration
        );

        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded)?;
        unknown
            .as_object_mut()
            .ok_or("configuration must serialize as an object")?
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert_eq!(
            failure(ProductionAuthorityConfiguration::from_json(
                &serde_json::to_vec(&unknown)?,
            ))?
            .code(),
            ProductionAuthorityErrorCode::InvalidConfiguration
        );
        assert_eq!(
            failure(ProductionAuthorityConfiguration::from_json(&vec![
                b' ';
                MAX_AUTHORITY_JSON_BYTES
                    + 1
            ]))?
            .code(),
            ProductionAuthorityErrorCode::LimitExceeded
        );

        let mut wildcard = fixture.configuration.clone();
        wildcard.runtime_audience = "*".to_owned();
        assert_eq!(
            failure(fixture.authority.reload(wildcard))?.code(),
            ProductionAuthorityErrorCode::InvalidConfiguration
        );

        let mut excess = fixture.configuration.clone();
        principal_mut(&mut excess)?.purposes = (0..=MAX_PURPOSES_PER_PRINCIPAL)
            .map(|value| format!("purpose-{value}"))
            .collect();
        assert_eq!(
            failure(fixture.authority.reload(excess))?.code(),
            ProductionAuthorityErrorCode::LimitExceeded
        );

        let mut missing_key = fixture.configuration.clone();
        tenant_mut(&mut missing_key)?.issuer_key_ref = KeyRef::new("missing-key")?;
        assert_eq!(
            failure(fixture.authority.reload(missing_key))?.code(),
            ProductionAuthorityErrorCode::KeyUnavailable
        );

        let unprotected = Arc::new(CompiledPolicyEngine::default());
        unprotected.install(policy_profile(false, 1), time(1)?)?;
        assert_eq!(
            failure(ProductionDomainAuthority::new(
                fixture.configuration.clone(),
                unprotected,
                fixture.keys.clone(),
                fixture.clock.clone(),
            ))?
            .code(),
            ProductionAuthorityErrorCode::InvalidConfiguration
        );
        Ok(())
    }

    #[test]
    fn exact_identity_catalog_contract_space_and_reference_authority_default_deny() -> TestResult<()>
    {
        let fixture = Fixture::new()?;
        let identity = resolved()?;
        let request = context("createSpace", "transport-principal")?;
        assert_eq!(
            DomainIdentityResolver::resolve(fixture.authority.as_ref(), &request)?,
            identity
        );
        assert_eq!(
            fixture
                .authority
                .resolve_authenticated(&authenticated("unknown-principal")?)?,
            None
        );
        let unknown_request = context("createSpace", "unknown-principal")?;
        assert_eq!(
            failure(DomainIdentityResolver::resolve(
                fixture.authority.as_ref(),
                &unknown_request,
            ))?
            .code(),
            DomainIdentityErrorCode::InvalidMapping
        );
        assert!(
            fixture
                .authority
                .is_operator(&authenticated("transport-principal")?)
        );
        assert!(
            !fixture
                .authority
                .is_operator(&authenticated("unknown-principal")?)
        );
        assert_eq!(fixture.authority.active_tenants()?, vec![record(1)?]);
        assert_eq!(fixture.authority.configured_tenant_ids()?, vec![record(1)?]);

        let catalog = fixture.authority.authorize_catalog(&identity, time(100)?)?;
        assert_eq!(catalog.project_ids, [record(2)?].into_iter().collect());
        assert!(!catalog.vector_allowed);
        assert_eq!(
            failure(fixture.authority.authorize_catalog(
                &ResolvedDomainIdentity {
                    tenant_id: record(1)?,
                    principal_id: record(99)?,
                },
                time(100)?,
            ))?,
            CatalogContextAuthorizationError::Denied
        );

        let allowed_contract = contract()?;
        let contract_authority =
            fixture
                .authority
                .authorize_contract(&identity, &allowed_contract, time(100)?)?;
        assert_eq!(contract_authority.purpose, "coding");
        let mut forged_principal = allowed_contract.clone();
        forged_principal.principal_id = record(99)?;
        assert_eq!(
            failure(fixture.authority.authorize_contract(
                &identity,
                &forged_principal,
                time(100)?,
            ))?,
            CatalogContextAuthorizationError::InvalidDecision
        );
        let mut forged_processor = allowed_contract.clone();
        forged_processor.target.provider = "unconfigured".to_owned();
        assert_eq!(
            failure(fixture.authority.authorize_contract(
                &identity,
                &forged_processor,
                time(100)?,
            ))?,
            CatalogContextAuthorizationError::Denied
        );
        let mut duplicate_project = allowed_contract;
        duplicate_project.project_ids.push(record(2)?);
        assert_eq!(
            failure(fixture.authority.authorize_contract(
                &identity,
                &duplicate_project,
                time(100)?,
            ))?,
            CatalogContextAuthorizationError::InvalidDecision
        );

        let scope = SpaceHandoffAuthorizationScope::NewSpace {
            project_id: record(2)?,
        };
        let space = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &request,
            &identity,
            &scope,
            time(100)?,
        )?;
        assert_eq!(space.effective.subject_id, record(3)?);
        assert_eq!(space.runtime_audience, "runtime-v1");
        assert_eq!(
            failure(SpaceHandoffAuthorizer::authorize(
                fixture.authority.as_ref(),
                &context("createSpace", "unknown-principal")?,
                &identity,
                &scope,
                time(100)?,
            ))?,
            DomainAuthorizationError::Denied
        );
        assert_eq!(
            failure(SpaceHandoffAuthorizer::authorize(
                fixture.authority.as_ref(),
                &context("getSpaceLog", "transport-principal")?,
                &identity,
                &scope,
                time(100)?,
            ))?,
            DomainAuthorizationError::Invalid
        );

        let handoff_context = context("createHandoff", "transport-principal")?;
        let handoff_scope = SpaceHandoffAuthorizationScope::NewHandoff;
        let handoff = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &handoff_context,
            &identity,
            &handoff_scope,
            time(100)?,
        )?;
        assert!(fixture.authority.reference_authorized(
            &handoff_context,
            &identity,
            &handoff_scope,
            &handoff.policy_digest,
            &version(80)?,
            time(100)?,
        )?);
        assert!(!fixture.authority.reference_authorized(
            &handoff_context,
            &identity,
            &handoff_scope,
            &digest(81)?,
            &version(80)?,
            time(100)?,
        )?);
        Ok(())
    }

    #[test]
    fn existing_space_authorization_cannot_use_ambient_access_from_another_project()
    -> TestResult<()> {
        let fixture = Fixture::new()?;
        let mut configuration = fixture.configuration.clone();
        tenant_mut(&mut configuration)?.project_ids.push(record(5)?);
        fixture.authority.reload(configuration)?;

        // The target space belongs to project 5, while the principal remains scoped only to
        // project 2. This assertion captures the current IDOR: the existing-space scope cannot
        // carry that immutable project binding, so production authorization incorrectly allows it.
        let result = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &context("getSpaceLog", "transport-principal")?,
            &resolved()?,
            &SpaceHandoffAuthorizationScope::Space {
                space_id: ContextSpaceId::new(record(6)?)?,
                project_id: record(5)?,
            },
            time(100)?,
        );
        assert_eq!(failure(result)?, DomainAuthorizationError::Denied);
        Ok(())
    }

    #[test]
    fn effect_api_and_worker_authority_require_exact_current_rules() -> TestResult<()> {
        let fixture = Fixture::new()?;
        let identity = resolved()?;
        let expected_capabilities: BTreeSet<_> = capabilities().into_iter().collect();
        let low = intent(RiskLevel::Low)?;
        assert_eq!(
            fixture.authority.evaluate(
                &context("prepareEffect", "transport-principal")?,
                &identity,
                EffectPolicyAction::Prepare,
                &low,
                None,
            )?,
            EffectPolicyDecision::new(true, expected_capabilities.clone())
        );

        let medium = intent(RiskLevel::Medium)?;
        let authorize_context = context("authorizeEffect", "transport-principal")?;
        assert_eq!(
            fixture.authority.evaluate(
                &authorize_context,
                &identity,
                EffectPolicyAction::Authorize,
                &medium,
                None,
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );
        assert_eq!(
            fixture.authority.evaluate(
                &authorize_context,
                &identity,
                EffectPolicyAction::Authorize,
                &medium,
                Some(ApprovalKind::Policy),
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );
        assert_eq!(
            fixture.authority.evaluate(
                &authorize_context,
                &identity,
                EffectPolicyAction::Authorize,
                &medium,
                Some(ApprovalKind::Human),
            )?,
            EffectPolicyDecision::new(true, expected_capabilities.clone())
        );

        let mut wrong_target = low.clone();
        wrong_target.target = "other-target".to_owned();
        assert_eq!(
            fixture.authority.evaluate(
                &context("prepareEffect", "transport-principal")?,
                &identity,
                EffectPolicyAction::Prepare,
                &wrong_target,
                None,
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );
        assert_eq!(
            fixture.authority.evaluate(
                &context("getEffectStatus", "transport-principal")?,
                &identity,
                EffectPolicyAction::Prepare,
                &low,
                None,
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );
        assert_eq!(
            fixture.authority.evaluate(
                &context("prepareEffect", "unknown-principal")?,
                &identity,
                EffectPolicyAction::Prepare,
                &low,
                None,
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );

        let durable_record = effect_record(low, record(3)?)?;
        let worker = EffectWorkerAuthority::authorize(
            fixture.authority.as_ref(),
            &record(1)?,
            EffectWorkerAction::Dispatch,
            &durable_record,
            time(100)?,
        )?;
        assert!(worker.policy_allows);
        assert_eq!(worker.actor_id, record(3)?);
        assert_eq!(worker.capabilities, expected_capabilities);
        let mut actorless = durable_record;
        actorless.journal.clear();
        assert!(
            EffectWorkerAuthority::authorize(
                fixture.authority.as_ref(),
                &record(1)?,
                EffectWorkerAction::Dispatch,
                &actorless,
                time(100)?,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn merge_planner_maps_every_result_once_and_rejects_forged_material() -> TestResult<()> {
        let fixture = Fixture::new()?;
        let identity = resolved()?;
        let merge_context = context("mergeHandoff", "transport-principal")?;
        let scope = SpaceHandoffAuthorizationScope::HandoffMerge {
            handoff_id: record(50)?,
            space_id: ContextSpaceId::new(record(70)?.as_str().to_owned())?,
            project_id: record(2)?,
        };
        let authorization = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &merge_context,
            &identity,
            &scope,
            time(100)?,
        )?;
        let material = merge_material(authorization.policy_digest.clone())?;
        let mappings = HandoffResultMergePlanner::plan_mappings(
            fixture.authority.as_ref(),
            &merge_context,
            &identity,
            &authorization,
            &material,
        )?;
        assert_eq!(mappings.len(), 3);
        let mapped: BTreeSet<_> = mappings
            .iter()
            .map(|mapping| mapping.version_id.clone())
            .collect();
        assert_eq!(
            mapped,
            [version(54)?, version(55)?, version(56)?]
                .into_iter()
                .collect()
        );
        let keys: BTreeSet<_> = mappings
            .iter()
            .map(|mapping| mapping.resource_key.clone())
            .collect();
        assert_eq!(keys.len(), mappings.len());

        let mut forged = material.clone();
        forged.capsule.issuer_id = record(99)?;
        assert_eq!(
            failure(HandoffResultMergePlanner::plan_mappings(
                fixture.authority.as_ref(),
                &merge_context,
                &identity,
                &authorization,
                &forged,
            ))?,
            SpaceHandoffDependencyError::Denied
        );
        let mut stale_authorization = authorization;
        stale_authorization.policy_digest = digest(99)?;
        assert_eq!(
            failure(HandoffResultMergePlanner::plan_mappings(
                fixture.authority.as_ref(),
                &merge_context,
                &identity,
                &stale_authorization,
                &material,
            ))?,
            SpaceHandoffDependencyError::Denied
        );
        Ok(())
    }

    #[test]
    fn reload_is_atomic_and_signing_key_rotation_requires_explicit_new_reference() -> TestResult<()>
    {
        let fixture = Fixture::new()?;
        let transport = authenticated("transport-principal")?;
        assert!(fixture.authority.is_operator(&transport));

        let mut invalid = fixture.configuration.clone();
        invalid.runtime_audience = "*".to_owned();
        assert!(fixture.authority.reload(invalid).is_err());
        assert!(fixture.authority.is_operator(&transport));

        let mut non_operator = fixture.configuration.clone();
        principal_mut(&mut non_operator)?.operator = false;
        fixture.authority.reload(non_operator)?;
        assert!(!fixture.authority.is_operator(&transport));
        fixture.authority.reload(fixture.configuration.clone())?;
        assert!(fixture.authority.is_operator(&transport));

        fixture.clock.set(time(101)?)?;
        let old_key = tenant(&fixture.configuration)?.issuer_key_ref.clone();
        let successor =
            fixture
                .keys
                .rotate(&old_key, record(1)?.as_str(), time(101)?.unix_nanos())?;
        let request = context("createSpace", "transport-principal")?;
        let scope = SpaceHandoffAuthorizationScope::NewSpace {
            project_id: record(2)?,
        };
        assert_eq!(
            failure(SpaceHandoffAuthorizer::authorize(
                fixture.authority.as_ref(),
                &request,
                &resolved()?,
                &scope,
                time(101)?,
            ))?,
            DomainAuthorizationError::Unavailable
        );
        assert_eq!(
            failure(fixture.authority.reload(fixture.configuration.clone()))?.code(),
            ProductionAuthorityErrorCode::KeyUnavailable
        );

        let mut rotated = fixture.configuration.clone();
        tenant_mut(&mut rotated)?.issuer_key_ref = successor.key_ref.clone();
        fixture.authority.reload(rotated.clone())?;
        let authorized = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &request,
            &resolved()?,
            &scope,
            time(101)?,
        )?;
        assert_eq!(authorized.issuer_key_ref, successor.key_ref);

        let mut self_revoked = rotated;
        tenant_mut(&mut self_revoked)?
            .revoked_key_refs
            .push(successor.key_ref.clone());
        assert_eq!(
            failure(fixture.authority.reload(self_revoked))?.code(),
            ProductionAuthorityErrorCode::InvalidConfiguration
        );
        let retained = SpaceHandoffAuthorizer::authorize(
            fixture.authority.as_ref(),
            &request,
            &resolved()?,
            &scope,
            time(101)?,
        )?;
        assert_eq!(retained.issuer_key_ref, successor.key_ref);
        Ok(())
    }

    #[test]
    fn durable_snapshot_roots_are_tenant_bound_and_recheck_current_key_authority() -> TestResult<()>
    {
        let fixture = Fixture::new()?;
        let tenant_id = record(1)?;
        let payload_digest = [0x5a; 32];
        let effect_signature = fixture
            .authority
            .sign_effect_record(&tenant_id, payload_digest)?;
        fixture
            .authority
            .verify_effect_record(&tenant_id, &payload_digest, &effect_signature)?;
        let authentication = fixture
            .authority
            .sign_snapshot_root(&tenant_id, payload_digest)?;
        fixture
            .authority
            .verify_snapshot_root(&tenant_id, &payload_digest, &authentication)?;

        let mut tampered_digest = payload_digest;
        tampered_digest[0] ^= 0xff;
        assert_eq!(
            failure(fixture.authority.verify_effect_record(
                &tenant_id,
                &tampered_digest,
                &effect_signature,
            ))?
            .code(),
            EffectErrorCode::CorruptJournal
        );
        assert_eq!(
            failure(fixture.authority.verify_snapshot_root(
                &tenant_id,
                &tampered_digest,
                &authentication,
            ))?
            .code(),
            DurableSnapshotErrorCode::InvalidSnapshot
        );
        assert_eq!(
            failure(fixture.authority.verify_snapshot_root(
                &record(999)?,
                &payload_digest,
                &authentication,
            ))?
            .code(),
            DurableSnapshotErrorCode::InvalidSnapshot
        );

        fixture.clock.set(time(101)?)?;
        let successor = fixture.keys.create(CreateKeyRequest {
            tenant: tenant_id.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: time(101)?.unix_nanos(),
            activated_at: time(101)?.unix_nanos(),
        })?;
        let mut rotated = fixture.configuration.clone();
        let tenant = tenant_mut(&mut rotated)?;
        tenant.issuer_key_ref = successor.key_ref;
        tenant.revoked_key_refs.push(authentication.key_ref.clone());
        fixture.authority.reload(rotated)?;
        assert_eq!(
            failure(fixture.authority.verify_snapshot_root(
                &tenant_id,
                &payload_digest,
                &authentication,
            ))?
            .code(),
            DurableSnapshotErrorCode::InvalidSnapshot
        );
        assert_eq!(
            failure(fixture.authority.verify_effect_record(
                &tenant_id,
                &payload_digest,
                &effect_signature,
            ))?
            .code(),
            EffectErrorCode::CorruptJournal
        );
        Ok(())
    }

    #[test]
    fn policy_and_configuration_revocations_and_expiry_fail_closed_immediately() -> TestResult<()> {
        let fixture = Fixture::new()?;
        let identity = resolved()?;
        let transport = authenticated("transport-principal")?;
        fixture.policy.revoke_grant(record(4)?, time(101)?)?;
        assert!(!fixture.authority.is_operator(&transport));
        assert_eq!(
            failure(fixture.authority.authorize_catalog(&identity, time(101)?))?,
            CatalogContextAuthorizationError::Denied
        );
        assert_eq!(
            failure(SpaceHandoffAuthorizer::authorize(
                fixture.authority.as_ref(),
                &context("createSpace", "transport-principal")?,
                &identity,
                &SpaceHandoffAuthorizationScope::NewSpace {
                    project_id: record(2)?,
                },
                time(101)?,
            ))?,
            DomainAuthorizationError::Denied
        );
        let effect = intent(RiskLevel::Low)?;
        assert_eq!(
            fixture.authority.evaluate(
                &context("prepareEffect", "transport-principal")?,
                &identity,
                EffectPolicyAction::Prepare,
                &effect,
                None,
            )?,
            EffectPolicyDecision::new(false, BTreeSet::new())
        );
        let worker_record = effect_record(effect, record(3)?)?;
        let worker = EffectWorkerAuthority::authorize(
            fixture.authority.as_ref(),
            &record(1)?,
            EffectWorkerAction::Dispatch,
            &worker_record,
            time(101)?,
        )?;
        assert!(!worker.policy_allows);
        assert!(worker.capabilities.is_empty());

        fixture.policy.set_available(false)?;
        assert!(!fixture.authority.is_operator(&transport));
        assert!(
            fixture
                .authority
                .evaluate(
                    &context("prepareEffect", "transport-principal")?,
                    &identity,
                    EffectPolicyAction::Prepare,
                    &worker_record.intent,
                    None,
                )
                .is_err()
        );
        assert_eq!(
            failure(fixture.authority.reload(fixture.configuration.clone()))?.code(),
            ProductionAuthorityErrorCode::PolicyUnavailable
        );
        fixture.policy.set_available(true)?;

        let separately_configured = Fixture::new()?;
        let mut revoked = separately_configured.configuration.clone();
        tenant_mut(&mut revoked)?
            .revoked_principal_ids
            .push(record(3)?);
        separately_configured.authority.reload(revoked)?;
        assert!(!separately_configured.authority.is_operator(&transport));
        assert_eq!(
            failure(
                separately_configured
                    .authority
                    .authorize_catalog(&identity, time(101)?),
            )?,
            CatalogContextAuthorizationError::Denied
        );

        let expiry = Fixture::new()?;
        expiry.clock.set(time(1_000)?)?;
        assert!(!expiry.authority.is_operator(&transport));
        assert_eq!(
            failure(expiry.authority.authorize_catalog(&identity, time(1_000)?),)?,
            CatalogContextAuthorizationError::Denied
        );
        Ok(())
    }
}
