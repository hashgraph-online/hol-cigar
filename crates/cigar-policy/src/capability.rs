//! Signature-bound capability grants and structural attenuation resolution.

use crate::{PolicyError, PolicyErrorCode};
use cigar_canon::{parse_strict_json, to_deterministic_cbor};
use cigar_crypto::{
    CryptoErrorCode, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest,
    SignatureVerification,
};
use cigar_protocol::{Capability, CapabilityGrant, RecordId, UtcTimestamp, Validate};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

const CAPABILITY_SIGNATURE_PURPOSE: &str = "cigar.capability-grant.v1";

/// Protocol grant plus a portable tenant- and principal-bound signature envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedCapabilityGrant {
    /// Exact attenuable grant.
    pub grant: CapabilityGrant,
    /// Scoped key-provider signature.
    pub signature: SignatureEnvelope,
}

impl fmt::Debug for SignedCapabilityGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCapabilityGrant")
            .field("grant", &self.grant)
            .field("signature", &self.signature)
            .finish()
    }
}

/// Effective authority fixed to a verified subject, tenant, scope, and expiry.
#[derive(Clone, Eq, PartialEq)]
pub struct EffectiveCapabilities {
    /// Authenticated tenant binding used to verify the signature.
    pub tenant: String,
    /// Verified subject principal.
    pub subject_id: RecordId,
    /// Verified grant identity.
    pub grant_id: RecordId,
    /// Exact granted operations.
    pub capabilities: BTreeSet<Capability>,
    /// Exact granted projects.
    pub project_ids: BTreeSet<RecordId>,
    /// Exact granted processors.
    pub processors: BTreeSet<String>,
    /// Exclusive authority expiry.
    pub expires_at: UtcTimestamp,
}

impl fmt::Debug for EffectiveCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveCapabilities")
            .field("tenant_bytes", &self.tenant.len())
            .field("subject_id", &self.subject_id)
            .field("grant_id", &self.grant_id)
            .field("capability_count", &self.capabilities.len())
            .field("project_count", &self.project_ids.len())
            .field("processor_count", &self.processors.len())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Capability signing and verification boundary backed by scoped key storage.
#[derive(Clone)]
pub struct CapabilityAuthority {
    provider: Arc<dyn KeyProvider>,
}

impl fmt::Debug for CapabilityAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityAuthority")
    }
}

impl CapabilityAuthority {
    /// Creates an authority around a key provider that never exports private key material.
    #[must_use]
    pub fn new(provider: Arc<dyn KeyProvider>) -> Self {
        Self { provider }
    }

    /// Validates and signs a grant under its issuer and exact temporal bounds.
    pub fn sign(
        &self,
        grant: CapabilityGrant,
        key_ref: &KeyRef,
        tenant: &str,
        signed_at: UtcTimestamp,
    ) -> Result<SignedCapabilityGrant, PolicyError> {
        grant
            .validate()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
        let payload_digest = grant_digest(&grant)?;
        let signature = self
            .provider
            .sign(SignatureRequest {
                key_ref,
                tenant,
                signer: grant.issuer_id.as_str(),
                purpose: CAPABILITY_SIGNATURE_PURPOSE,
                payload_digest,
                signed_at: signed_at.unix_nanos(),
                expires_at: Some(grant.expires_at.unix_nanos()),
            })
            .map_err(map_crypto_error)?;
        Ok(SignedCapabilityGrant { grant, signature })
    }

    /// Verifies signature, current subject, time, revocation, and optional parent attenuation.
    pub fn verify(
        &self,
        signed: &SignedCapabilityGrant,
        tenant: &str,
        expected_subject: &RecordId,
        now: UtcTimestamp,
        revoked_grants: &BTreeSet<RecordId>,
        parent: Option<&SignedCapabilityGrant>,
    ) -> Result<EffectiveCapabilities, PolicyError> {
        if let Some(parent) = parent {
            self.verify_chain(
                signed,
                tenant,
                expected_subject,
                now,
                revoked_grants,
                std::slice::from_ref(parent),
            )
        } else {
            self.verify_chain(signed, tenant, expected_subject, now, revoked_grants, &[])
        }
    }

    /// Verifies an arbitrary immediate-parent-first attenuation chain through its root.
    pub fn verify_chain(
        &self,
        signed: &SignedCapabilityGrant,
        tenant: &str,
        expected_subject: &RecordId,
        now: UtcTimestamp,
        revoked_grants: &BTreeSet<RecordId>,
        ancestors: &[SignedCapabilityGrant],
    ) -> Result<EffectiveCapabilities, PolicyError> {
        if &signed.grant.subject_id != expected_subject {
            return Err(PolicyError::new(PolicyErrorCode::InvalidCapability));
        }
        self.verify_signed(signed, tenant, now, revoked_grants)?;
        let mut child = &signed.grant;
        for parent in ancestors {
            if child.parent_grant_id.as_ref() != Some(&parent.grant.grant_id)
                || child.issuer_id != parent.grant.subject_id
            {
                return Err(PolicyError::new(PolicyErrorCode::InvalidCapability));
            }
            self.verify_signed(parent, tenant, now, revoked_grants)?;
            child
                .validate_attenuation_of(&parent.grant)
                .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
            child = &parent.grant;
        }
        if child.parent_grant_id.is_some() {
            return Err(PolicyError::new(PolicyErrorCode::InvalidCapability));
        }
        Ok(EffectiveCapabilities {
            tenant: tenant.to_owned(),
            subject_id: signed.grant.subject_id.clone(),
            grant_id: signed.grant.grant_id.clone(),
            capabilities: signed.grant.capabilities.iter().copied().collect(),
            project_ids: signed.grant.project_ids.iter().cloned().collect(),
            processors: signed.grant.processors.iter().cloned().collect(),
            expires_at: signed.grant.expires_at,
        })
    }

    fn verify_signed(
        &self,
        signed: &SignedCapabilityGrant,
        tenant: &str,
        now: UtcTimestamp,
        revoked_grants: &BTreeSet<RecordId>,
    ) -> Result<(), PolicyError> {
        signed
            .grant
            .validate()
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
        if now < signed.grant.not_before
            || now >= signed.grant.expires_at
            || revoked_grants.contains(&signed.grant.grant_id)
        {
            return Err(PolicyError::new(
                if revoked_grants.contains(&signed.grant.grant_id) {
                    PolicyErrorCode::Revoked
                } else {
                    PolicyErrorCode::InvalidCapability
                },
            ));
        }
        let payload_digest = grant_digest(&signed.grant)?;
        self.provider
            .verify(
                &signed.signature,
                SignatureVerification {
                    tenant,
                    signer: signed.grant.issuer_id.as_str(),
                    purpose: CAPABILITY_SIGNATURE_PURPOSE,
                    payload_digest: &payload_digest,
                    now: now.unix_nanos(),
                },
            )
            .map_err(map_crypto_error)
    }

    /// Checks structural attenuation before a child grant is signed.
    pub fn validate_attenuation(
        &self,
        child: &CapabilityGrant,
        parent: &CapabilityGrant,
    ) -> Result<(), PolicyError> {
        child
            .validate()
            .and_then(|()| child.validate_attenuation_of(parent))
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))
    }
}

fn grant_digest(grant: &CapabilityGrant) -> Result<[u8; 32], PolicyError> {
    let json = serde_json::to_vec(grant)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
    let node = parse_strict_json(&json)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
    let cbor = to_deterministic_cbor(&node)
        .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidCapability))?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CAPABILITY-GRANT\0v1\0");
    hasher.update(cbor);
    Ok(hasher.finalize().into())
}

fn map_crypto_error(error: cigar_crypto::CryptoError) -> PolicyError {
    if error.code() == CryptoErrorCode::ProviderUnavailable {
        PolicyError::new(PolicyErrorCode::Unavailable)
    } else {
        PolicyError::new(PolicyErrorCode::InvalidCapability)
    }
}
