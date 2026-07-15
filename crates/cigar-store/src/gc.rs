//! Signed, revision-bound repository garbage-collection plans.

use crate::{
    GarbageCollectionPolicy, RepositoryGarbageCollectionCandidate, StoreError, StoreErrorCode,
    StoreRevision,
};
use cigar_crypto::{
    CryptoErrorCode, KeyAlgorithm, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest,
    SignatureVerification,
};
use cigar_protocol::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

const GC_PLAN_SCHEMA: &str = "cigar.repository-gc-plan.v1";
const GC_PLAN_PURPOSE: &str = "repository-gc-plan-v1";
const MAX_GC_PLAN_CANDIDATES: usize = 1_000_000;

/// Stable, content-free signed-plan failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GarbageCollectionPlanErrorCode {
    /// The plan shape, bounds, ordering, or signer metadata is invalid.
    InvalidMetadata,
    /// The plan root or signature does not authenticate the supplied semantics.
    Corrupt,
    /// The signing or verification key is unavailable or unusable.
    KeyUnavailable,
    /// The authenticated signer is rejected by current trust policy.
    UntrustedSigner,
}

/// Content-free signed-plan error safe for operator diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GarbageCollectionPlanError {
    code: GarbageCollectionPlanErrorCode,
}

impl GarbageCollectionPlanError {
    const fn new(code: GarbageCollectionPlanErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> GarbageCollectionPlanErrorCode {
        self.code
    }
}

impl fmt::Debug for GarbageCollectionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GarbageCollectionPlanError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for GarbageCollectionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "garbage-collection plan failed: {:?}", self.code)
    }
}

impl std::error::Error for GarbageCollectionPlanError {}

/// Exact repository revision, policy, bound, and candidate set approved for one GC run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GarbageCollectionPlan {
    schema_version: String,
    repository_revision: u64,
    created_at_unix_nanos: i128,
    policy: GarbageCollectionPolicy,
    maximum_candidates: u64,
    candidates: Vec<RepositoryGarbageCollectionCandidate>,
    candidate_root: ContentDigest,
}

impl GarbageCollectionPlan {
    pub(crate) fn new(
        revision: StoreRevision,
        created_at_unix_nanos: i128,
        policy: GarbageCollectionPolicy,
        maximum_candidates: usize,
        candidates: Vec<RepositoryGarbageCollectionCandidate>,
    ) -> Result<Self, StoreError> {
        let maximum_candidates = u64::try_from(maximum_candidates)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let candidate_root = candidate_root(&candidates)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        let plan = Self {
            schema_version: GC_PLAN_SCHEMA.to_owned(),
            repository_revision: revision.0,
            created_at_unix_nanos,
            policy,
            maximum_candidates,
            candidates,
            candidate_root,
        };
        plan.validate()
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        Ok(plan)
    }

    /// Returns the exact metadata revision observed while candidates were selected.
    #[must_use]
    pub const fn repository_revision(&self) -> StoreRevision {
        StoreRevision(self.repository_revision)
    }

    /// Returns the semantic instant at which the plan was signed.
    #[must_use]
    pub const fn created_at_unix_nanos(&self) -> i128 {
        self.created_at_unix_nanos
    }

    /// Returns the retention, legal-hold, and backup deletion preconditions.
    #[must_use]
    pub const fn policy(&self) -> GarbageCollectionPolicy {
        self.policy
    }

    /// Returns the exact maximum selection bound used by the plan.
    #[must_use]
    pub fn maximum_candidates(&self) -> usize {
        usize::try_from(self.maximum_candidates).unwrap_or(usize::MAX)
    }

    /// Returns the exact ordered candidate set authenticated by the plan.
    #[must_use]
    pub fn candidates(&self) -> &[RepositoryGarbageCollectionCandidate] {
        &self.candidates
    }

    /// Returns the domain-separated root over the exact candidate set.
    #[must_use]
    pub const fn candidate_root(&self) -> &ContentDigest {
        &self.candidate_root
    }

    fn validate(&self) -> Result<(), GarbageCollectionPlanError> {
        let maximum_candidates =
            usize::try_from(self.maximum_candidates).map_err(|_error| invalid_metadata())?;
        if self.schema_version != GC_PLAN_SCHEMA
            || self.created_at_unix_nanos < 0
            || maximum_candidates == 0
            || maximum_candidates > MAX_GC_PLAN_CANDIDATES
            || self.candidates.len() > maximum_candidates
            || self.candidates.windows(2).any(|pair| {
                pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
                    (&left.tenant_id, &left.digest) >= (&right.tenant_id, &right.digest)
                })
            })
        {
            return Err(invalid_metadata());
        }
        if candidate_root(&self.candidates)? != self.candidate_root {
            return Err(GarbageCollectionPlanError::new(
                GarbageCollectionPlanErrorCode::Corrupt,
            ));
        }
        Ok(())
    }
}

/// Identity and semantic time used to sign one exact GC plan.
#[derive(Clone, Copy, Debug)]
pub struct GarbageCollectionPlanIdentity<'a> {
    /// Active tenant signing key.
    pub signing_key: &'a KeyRef,
    /// Tenant owning the operator identity.
    pub tenant: &'a str,
    /// Authenticated operator principal.
    pub signer: &'a str,
}

/// Authenticated identity embedded in a signed GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GarbageCollectionPlanSignatureIdentity {
    /// Tenant whose key signed the plan.
    pub tenant: String,
    /// Operator principal recorded in the signature.
    pub signer: String,
    /// Exact active or retained signing key used by the plan.
    pub signing_key: KeyRef,
    /// Semantic signing time, equal to the plan creation time.
    pub signed_at_unix_nanos: i128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPlanSignature {
    algorithm: String,
    key_ref: String,
    tenant: String,
    signer: String,
    purpose: String,
    signed_at_unix_nanos: i128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix_nanos: Option<i128>,
    payload_digest: Vec<u8>,
    signature: Vec<u8>,
}

/// Portable signed plan document suitable for owner-private JSON persistence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGarbageCollectionPlan {
    plan: GarbageCollectionPlan,
    signature: PersistedPlanSignature,
}

impl SignedGarbageCollectionPlan {
    /// Returns the signed semantic plan without treating it as verified authorization.
    #[must_use]
    pub const fn unverified_plan(&self) -> &GarbageCollectionPlan {
        &self.plan
    }
}

/// Opaque plan returned only after cryptographic verification and current trust evaluation.
pub struct VerifiedGarbageCollectionPlan {
    signed: SignedGarbageCollectionPlan,
    identity: GarbageCollectionPlanSignatureIdentity,
}

impl VerifiedGarbageCollectionPlan {
    /// Returns the authenticated semantic plan.
    #[must_use]
    pub const fn plan(&self) -> &GarbageCollectionPlan {
        &self.signed.plan
    }

    /// Returns the authenticated operator identity.
    #[must_use]
    pub const fn identity(&self) -> &GarbageCollectionPlanSignatureIdentity {
        &self.identity
    }
}

/// Signs an exact repository-derived plan with a purpose-separated operator signature.
pub fn sign_garbage_collection_plan<P: KeyProvider>(
    plan: GarbageCollectionPlan,
    provider: &P,
    identity: GarbageCollectionPlanIdentity<'_>,
) -> Result<SignedGarbageCollectionPlan, GarbageCollectionPlanError> {
    plan.validate()?;
    validate_identity(identity.tenant, identity.signer, plan.created_at_unix_nanos)?;
    let payload_digest = plan_payload_digest(&plan)?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: identity.signing_key,
            tenant: identity.tenant,
            signer: identity.signer,
            purpose: GC_PLAN_PURPOSE,
            payload_digest,
            signed_at: plan.created_at_unix_nanos,
            expires_at: None,
        })
        .map_err(map_crypto_error)?;
    Ok(SignedGarbageCollectionPlan {
        plan,
        signature: persisted_signature(&signature, identity.tenant),
    })
}

/// Verifies a signed plan and applies the caller's current trust policy to its embedded identity.
pub fn verify_garbage_collection_plan_trusted<P, F>(
    signed: SignedGarbageCollectionPlan,
    provider: &P,
    now_unix_nanos: i128,
    trust: F,
) -> Result<VerifiedGarbageCollectionPlan, GarbageCollectionPlanError>
where
    P: KeyProvider,
    F: Fn(&GarbageCollectionPlanSignatureIdentity) -> bool,
{
    signed.plan.validate()?;
    let signature = restored_signature(&signed.signature)?;
    let identity = GarbageCollectionPlanSignatureIdentity {
        tenant: signed.signature.tenant.clone(),
        signer: signature.signer.clone(),
        signing_key: signature.key_ref.clone(),
        signed_at_unix_nanos: signature.signed_at,
    };
    validate_identity(
        &identity.tenant,
        &identity.signer,
        identity.signed_at_unix_nanos,
    )?;
    if signature.purpose != GC_PLAN_PURPOSE
        || signature.expires_at.is_some()
        || signature.signed_at != signed.plan.created_at_unix_nanos
    {
        return Err(GarbageCollectionPlanError::new(
            GarbageCollectionPlanErrorCode::Corrupt,
        ));
    }
    if !trust(&identity) {
        return Err(GarbageCollectionPlanError::new(
            GarbageCollectionPlanErrorCode::UntrustedSigner,
        ));
    }
    let payload_digest = plan_payload_digest(&signed.plan)?;
    if signature.payload_digest != payload_digest {
        return Err(GarbageCollectionPlanError::new(
            GarbageCollectionPlanErrorCode::Corrupt,
        ));
    }
    provider
        .verify(
            &signature,
            SignatureVerification {
                tenant: &identity.tenant,
                signer: &identity.signer,
                purpose: GC_PLAN_PURPOSE,
                payload_digest: &payload_digest,
                now: now_unix_nanos,
            },
        )
        .map_err(map_crypto_error)?;
    Ok(VerifiedGarbageCollectionPlan { signed, identity })
}

fn persisted_signature(signature: &SignatureEnvelope, tenant: &str) -> PersistedPlanSignature {
    PersistedPlanSignature {
        algorithm: "ed25519".to_owned(),
        key_ref: signature.key_ref.as_str().to_owned(),
        tenant: tenant.to_owned(),
        signer: signature.signer.clone(),
        purpose: signature.purpose.clone(),
        signed_at_unix_nanos: signature.signed_at,
        expires_at_unix_nanos: signature.expires_at,
        payload_digest: signature.payload_digest.to_vec(),
        signature: signature.signature.to_vec(),
    }
}

fn restored_signature(
    persisted: &PersistedPlanSignature,
) -> Result<SignatureEnvelope, GarbageCollectionPlanError> {
    if persisted.algorithm != "ed25519" {
        return Err(invalid_metadata());
    }
    Ok(SignatureEnvelope {
        algorithm: KeyAlgorithm::Ed25519,
        key_ref: KeyRef::new(persisted.key_ref.clone()).map_err(|_error| invalid_metadata())?,
        signer: persisted.signer.clone(),
        purpose: persisted.purpose.clone(),
        signed_at: persisted.signed_at_unix_nanos,
        expires_at: persisted.expires_at_unix_nanos,
        payload_digest: persisted
            .payload_digest
            .clone()
            .try_into()
            .map_err(|_error| invalid_metadata())?,
        signature: persisted
            .signature
            .clone()
            .try_into()
            .map_err(|_error| invalid_metadata())?,
    })
}

fn validate_identity(
    tenant: &str,
    signer: &str,
    signed_at_unix_nanos: i128,
) -> Result<(), GarbageCollectionPlanError> {
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    if signed_at_unix_nanos < 0 || !valid(tenant) || !valid(signer) {
        Err(invalid_metadata())
    } else {
        Ok(())
    }
}

fn plan_payload_digest(
    plan: &GarbageCollectionPlan,
) -> Result<[u8; 32], GarbageCollectionPlanError> {
    let encoded = serde_json::to_vec(plan).map_err(|_error| invalid_metadata())?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-REPOSITORY-GC-PLAN-SIGNATURE\0v1\0");
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_error| invalid_metadata())?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn candidate_root(
    candidates: &[RepositoryGarbageCollectionCandidate],
) -> Result<ContentDigest, GarbageCollectionPlanError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-REPOSITORY-GC-CANDIDATES\0v1\0");
    hasher.update(
        u64::try_from(candidates.len())
            .map_err(|_error| invalid_metadata())?
            .to_be_bytes(),
    );
    for candidate in candidates {
        for value in [candidate.tenant_id.as_str(), candidate.digest.as_str()] {
            hasher.update(
                u64::try_from(value.len())
                    .map_err(|_error| invalid_metadata())?
                    .to_be_bytes(),
            );
            hasher.update(value.as_bytes());
        }
    }
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| invalid_metadata())?;
    }
    ContentDigest::new(encoded).map_err(|_error| invalid_metadata())
}

fn invalid_metadata() -> GarbageCollectionPlanError {
    GarbageCollectionPlanError::new(GarbageCollectionPlanErrorCode::InvalidMetadata)
}

fn map_crypto_error(error: cigar_crypto::CryptoError) -> GarbageCollectionPlanError {
    match error.code() {
        CryptoErrorCode::SignatureInvalid | CryptoErrorCode::AuthenticationFailed => {
            GarbageCollectionPlanError::new(GarbageCollectionPlanErrorCode::Corrupt)
        }
        _ => GarbageCollectionPlanError::new(GarbageCollectionPlanErrorCode::KeyUnavailable),
    }
}
