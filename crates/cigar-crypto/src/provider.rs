//! Scoped key lifecycle and signature-envelope provider.

use super::{
    CryptoError, CryptoErrorCode, ED25519_PUBLIC_BYTES, EncryptedEnvelope, SecretBytes,
    decrypt_xchacha20, ed25519_public_key, encrypt_xchacha20, generate_ed25519_secret,
    generate_xchacha20_key, sign_ed25519, verify_ed25519,
};
use cigar_canon::{CanonicalNode, to_deterministic_cbor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

const MAX_KEY_REF_BYTES: usize = 128;
const MAX_SCOPE_BYTES: usize = 256;
const KEY_REFERENCE_ATTEMPTS: usize = 16;

/// Opaque bounded provider key reference.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyRef(String);

impl KeyRef {
    /// Parses a normalized opaque key reference.
    pub fn new(value: impl Into<String>) -> Result<Self, CryptoError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_KEY_REF_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if valid {
            Ok(Self(value))
        } else {
            Err(CryptoError::new(CryptoErrorCode::InvalidMetadata))
        }
    }

    /// Returns the normalized provider reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("KeyRef").field(&self.0).finish()
    }
}

/// Non-interchangeable semantic key purposes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyPurpose {
    /// Ed25519 signing and verification.
    Signing,
    /// XChaCha20-Poly1305 data-key wrapping.
    BlobEncryption,
}

/// Frozen v1 key algorithms.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyAlgorithm {
    /// Ed25519 signatures.
    Ed25519,
    /// XChaCha20-Poly1305 authenticated encryption.
    XChaCha20Poly1305,
}

/// Key lifecycle status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyStatus {
    /// Key may authorize its declared operation.
    Active,
    /// Key is retained for historical verification only.
    Retired,
    /// Private material was zeroized and cannot be used.
    Destroyed,
}

/// Public, tenant-scoped key metadata. Private bytes are never represented here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyMetadata {
    /// Opaque provider reference.
    pub key_ref: KeyRef,
    /// Non-interchangeable purpose.
    pub purpose: KeyPurpose,
    /// Exact algorithm.
    pub algorithm: KeyAlgorithm,
    /// Owning tenant selector.
    pub tenant: String,
    /// Metadata creation time in Unix nanoseconds.
    pub created_at: i128,
    /// First permitted use time in Unix nanoseconds.
    pub activated_at: i128,
    /// Retirement or destruction time, if no longer active.
    pub deactivated_at: Option<i128>,
    /// Current lifecycle state.
    pub status: KeyStatus,
    /// Ed25519 public identity when this is a signing key.
    pub public_identity: Option<[u8; ED25519_PUBLIC_BYTES]>,
}

/// Validated key creation parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateKeyRequest {
    /// Owning tenant selector.
    pub tenant: String,
    /// Requested non-interchangeable purpose.
    pub purpose: KeyPurpose,
    /// Requested exact algorithm.
    pub algorithm: KeyAlgorithm,
    /// Metadata creation time in Unix nanoseconds.
    pub created_at: i128,
    /// First permitted use time in Unix nanoseconds.
    pub activated_at: i128,
}

/// Portable purpose- and identity-bound signature envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct SignatureEnvelope {
    /// Signing algorithm.
    pub algorithm: KeyAlgorithm,
    /// Provider key reference.
    pub key_ref: KeyRef,
    /// Signer principal selector.
    pub signer: String,
    /// Exact semantic signature purpose.
    pub purpose: String,
    /// Signing time in Unix nanoseconds.
    pub signed_at: i128,
    /// Exclusive envelope expiry when applicable.
    pub expires_at: Option<i128>,
    /// Domain-separated semantic payload digest.
    pub payload_digest: [u8; 32],
    /// Ed25519 signature bytes.
    pub signature: [u8; 64],
}

impl fmt::Debug for SignatureEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignatureEnvelope")
            .field("algorithm", &self.algorithm)
            .field("key_ref", &self.key_ref)
            .field("signer_bytes", &self.signer.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("signed_at", &self.signed_at)
            .field("expires_at", &self.expires_at)
            .field("signature_bytes", &self.signature.len())
            .finish_non_exhaustive()
    }
}

/// Exact expectations applied during signature verification.
#[derive(Clone, Copy, Debug)]
pub struct SignatureVerification<'a> {
    /// Expected tenant owner of the signing key.
    pub tenant: &'a str,
    /// Expected signer principal.
    pub signer: &'a str,
    /// Expected semantic purpose.
    pub purpose: &'a str,
    /// Expected domain-separated payload digest.
    pub payload_digest: &'a [u8; 32],
    /// Current Unix nanoseconds for expiry checks.
    pub now: i128,
}

/// Fully scoped request for creating a signature envelope.
#[derive(Clone, Copy, Debug)]
pub struct SignatureRequest<'a> {
    /// Active signing key reference.
    pub key_ref: &'a KeyRef,
    /// Expected key tenant.
    pub tenant: &'a str,
    /// Authenticated signer principal.
    pub signer: &'a str,
    /// Exact semantic signature purpose.
    pub purpose: &'a str,
    /// Domain-separated payload digest.
    pub payload_digest: [u8; 32],
    /// Signing time in Unix nanoseconds.
    pub signed_at: i128,
    /// Exclusive expiry when applicable.
    pub expires_at: Option<i128>,
}

/// Key provider contract. Signing and master-key bytes never cross this boundary.
pub trait KeyProvider: Send + Sync {
    /// Creates a new scoped key.
    fn create(&self, request: CreateKeyRequest) -> Result<KeyMetadata, CryptoError>;

    /// Resolves active public metadata for an exact tenant, purpose, and time.
    fn resolve(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        purpose: KeyPurpose,
        at: i128,
    ) -> Result<KeyMetadata, CryptoError>;

    /// Retires an active key and creates its successor atomically.
    fn rotate(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        activated_at: i128,
    ) -> Result<KeyMetadata, CryptoError>;

    /// Signs a digest in a fully bound envelope.
    fn sign(&self, request: SignatureRequest<'_>) -> Result<SignatureEnvelope, CryptoError>;

    /// Verifies signature bytes, scope, key status at signing, and expiry.
    fn verify(
        &self,
        envelope: &SignatureEnvelope,
        expectation: SignatureVerification<'_>,
    ) -> Result<(), CryptoError>;

    /// Wraps a data-encryption key under an active tenant master key.
    fn wrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        data_key: &SecretBytes,
        associated_data: &[u8],
        at: i128,
    ) -> Result<EncryptedEnvelope, CryptoError>;

    /// Unwraps a data-encryption key only under identical tenant scope and associated data.
    fn unwrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        envelope: &EncryptedEnvelope,
        associated_data: &[u8],
        at: i128,
    ) -> Result<SecretBytes, CryptoError>;

    /// Zeroizes private material and permanently disables new operations.
    fn destroy(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        destroyed_at: i128,
    ) -> Result<KeyMetadata, CryptoError>;
}

/// Read-only capability wrapper for externally provisioned multi-replica key material.
///
/// Resolve, sign, verify, wrap, and unwrap remain available. Every lifecycle mutation is denied,
/// preventing a serving process from rotating or replacing a shared mounted key set.
pub struct ImmutableKeyProvider<P: KeyProvider> {
    inner: Arc<P>,
}

impl<P: KeyProvider> ImmutableKeyProvider<P> {
    /// Restricts an already provisioned provider to non-mutating operations.
    #[must_use]
    pub const fn new(inner: Arc<P>) -> Self {
        Self { inner }
    }
}

impl<P: KeyProvider> fmt::Debug for ImmutableKeyProvider<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImmutableKeyProvider([REDACTED])")
    }
}

impl<P: KeyProvider> KeyProvider for ImmutableKeyProvider<P> {
    fn create(&self, _request: CreateKeyRequest) -> Result<KeyMetadata, CryptoError> {
        Err(CryptoError::new(CryptoErrorCode::ScopeDenied))
    }

    fn resolve(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        purpose: KeyPurpose,
        at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        self.inner.resolve(key_ref, tenant, purpose, at)
    }

    fn rotate(
        &self,
        _key_ref: &KeyRef,
        _tenant: &str,
        _activated_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        Err(CryptoError::new(CryptoErrorCode::ScopeDenied))
    }

    fn sign(&self, request: SignatureRequest<'_>) -> Result<SignatureEnvelope, CryptoError> {
        self.inner.sign(request)
    }

    fn verify(
        &self,
        envelope: &SignatureEnvelope,
        expectation: SignatureVerification<'_>,
    ) -> Result<(), CryptoError> {
        self.inner.verify(envelope, expectation)
    }

    fn wrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        data_key: &SecretBytes,
        associated_data: &[u8],
        at: i128,
    ) -> Result<EncryptedEnvelope, CryptoError> {
        self.inner
            .wrap(key_ref, tenant, data_key, associated_data, at)
    }

    fn unwrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        envelope: &EncryptedEnvelope,
        associated_data: &[u8],
        at: i128,
    ) -> Result<SecretBytes, CryptoError> {
        self.inner
            .unwrap(key_ref, tenant, envelope, associated_data, at)
    }

    fn destroy(
        &self,
        _key_ref: &KeyRef,
        _tenant: &str,
        _destroyed_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        Err(CryptoError::new(CryptoErrorCode::ScopeDenied))
    }
}

pub(super) struct StoredKey {
    pub(super) metadata: KeyMetadata,
    pub(super) material: Option<SecretBytes>,
}

/// Hermetic in-memory provider used as the behavioral key-provider oracle.
#[derive(Default)]
pub struct MemoryKeyProvider {
    pub(super) keys: Mutex<BTreeMap<KeyRef, StoredKey>>,
}

impl fmt::Debug for MemoryKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemoryKeyProvider([REDACTED])")
    }
}

impl MemoryKeyProvider {
    pub(super) fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<KeyRef, StoredKey>>, CryptoError> {
        self.keys
            .lock()
            .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn create(&self, request: CreateKeyRequest) -> Result<KeyMetadata, CryptoError> {
        validate_create_request(&request)?;
        let (material, public_identity) = generate_material(request.algorithm)?;
        let mut keys = self.lock()?;
        let key_ref = unique_key_ref(&keys)?;
        let metadata = KeyMetadata {
            key_ref: key_ref.clone(),
            purpose: request.purpose,
            algorithm: request.algorithm,
            tenant: request.tenant,
            created_at: request.created_at,
            activated_at: request.activated_at,
            deactivated_at: None,
            status: KeyStatus::Active,
            public_identity,
        };
        keys.insert(
            key_ref,
            StoredKey {
                metadata: metadata.clone(),
                material: Some(material),
            },
        );
        Ok(metadata)
    }

    fn resolve(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        purpose: KeyPurpose,
        at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        let keys = self.lock()?;
        let stored = scoped_key(&keys, key_ref, tenant)?;
        require_usable(stored, purpose, at)?;
        Ok(stored.metadata.clone())
    }

    fn rotate(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        activated_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        let mut keys = self.lock()?;
        let (purpose, algorithm, tenant) = {
            let current = scoped_key(&keys, key_ref, tenant)?;
            require_usable(current, current.metadata.purpose, activated_at)?;
            if activated_at < current.metadata.created_at {
                return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
            }
            (
                current.metadata.purpose,
                current.metadata.algorithm,
                current.metadata.tenant.clone(),
            )
        };
        let (material, public_identity) = generate_material(algorithm)?;
        let successor_ref = unique_key_ref(&keys)?;
        let successor = KeyMetadata {
            key_ref: successor_ref.clone(),
            purpose,
            algorithm,
            tenant: tenant.clone(),
            created_at: activated_at,
            activated_at,
            deactivated_at: None,
            status: KeyStatus::Active,
            public_identity,
        };
        let current = scoped_key_mut(&mut keys, key_ref, &tenant)?;
        current.metadata.status = KeyStatus::Retired;
        current.metadata.deactivated_at = Some(activated_at);
        keys.insert(
            successor_ref,
            StoredKey {
                metadata: successor.clone(),
                material: Some(material),
            },
        );
        Ok(successor)
    }

    fn sign(&self, request: SignatureRequest<'_>) -> Result<SignatureEnvelope, CryptoError> {
        validate_scope(request.signer)?;
        validate_scope(request.purpose)?;
        if request
            .expires_at
            .is_some_and(|expiry| expiry <= request.signed_at)
        {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        let keys = self.lock()?;
        let stored = scoped_key(&keys, request.key_ref, request.tenant)?;
        require_usable(stored, KeyPurpose::Signing, request.signed_at)?;
        let mut envelope = SignatureEnvelope {
            algorithm: KeyAlgorithm::Ed25519,
            key_ref: request.key_ref.clone(),
            signer: request.signer.to_owned(),
            purpose: request.purpose.to_owned(),
            signed_at: request.signed_at,
            expires_at: request.expires_at,
            payload_digest: request.payload_digest,
            signature: [0; 64],
        };
        let input = signature_input(&envelope)?;
        let material = stored
            .material
            .as_ref()
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::KeyInactive))?;
        envelope.signature = sign_ed25519(material, &input)?;
        Ok(envelope)
    }

    fn verify(
        &self,
        envelope: &SignatureEnvelope,
        expectation: SignatureVerification<'_>,
    ) -> Result<(), CryptoError> {
        if envelope.algorithm != KeyAlgorithm::Ed25519
            || envelope.signer != expectation.signer
            || envelope.purpose != expectation.purpose
            || envelope.payload_digest != *expectation.payload_digest
        {
            return Err(CryptoError::new(CryptoErrorCode::ScopeDenied));
        }
        if envelope.signed_at > expectation.now
            || envelope
                .expires_at
                .is_some_and(|expiry| expectation.now >= expiry)
        {
            return Err(CryptoError::new(CryptoErrorCode::SignatureExpired));
        }
        let keys = self.lock()?;
        let stored = scoped_key(&keys, &envelope.key_ref, expectation.tenant)?;
        if stored.metadata.purpose != KeyPurpose::Signing
            || stored.metadata.algorithm != KeyAlgorithm::Ed25519
            || envelope.signed_at < stored.metadata.activated_at
            || stored
                .metadata
                .deactivated_at
                .is_some_and(|time| envelope.signed_at >= time)
        {
            return Err(CryptoError::new(CryptoErrorCode::KeyInactive));
        }
        let public_key = stored
            .metadata
            .public_identity
            .as_ref()
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
        verify_ed25519(public_key, &signature_input(envelope)?, &envelope.signature)
    }

    fn wrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        data_key: &SecretBytes,
        associated_data: &[u8],
        at: i128,
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let keys = self.lock()?;
        let stored = scoped_key(&keys, key_ref, tenant)?;
        require_usable(stored, KeyPurpose::BlobEncryption, at)?;
        let material = stored
            .material
            .as_ref()
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::KeyInactive))?;
        encrypt_xchacha20(material, data_key.expose(), associated_data)
    }

    fn unwrap(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        envelope: &EncryptedEnvelope,
        associated_data: &[u8],
        at: i128,
    ) -> Result<SecretBytes, CryptoError> {
        let keys = self.lock()?;
        let stored = scoped_key(&keys, key_ref, tenant)?;
        require_decryptable(stored, KeyPurpose::BlobEncryption, at)?;
        let material = stored
            .material
            .as_ref()
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::KeyInactive))?;
        decrypt_xchacha20(material, envelope, associated_data)
    }

    fn destroy(
        &self,
        key_ref: &KeyRef,
        tenant: &str,
        destroyed_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        let mut keys = self.lock()?;
        let stored = scoped_key_mut(&mut keys, key_ref, tenant)?;
        if stored.metadata.status == KeyStatus::Destroyed
            || destroyed_at < stored.metadata.created_at
        {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        stored.material = None;
        stored.metadata.status = KeyStatus::Destroyed;
        stored.metadata.deactivated_at = Some(destroyed_at);
        Ok(stored.metadata.clone())
    }
}

fn validate_create_request(request: &CreateKeyRequest) -> Result<(), CryptoError> {
    validate_scope(&request.tenant)?;
    if request.activated_at < request.created_at
        || !matches!(
            (request.purpose, request.algorithm),
            (KeyPurpose::Signing, KeyAlgorithm::Ed25519)
                | (KeyPurpose::BlobEncryption, KeyAlgorithm::XChaCha20Poly1305)
        )
    {
        return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
    }
    Ok(())
}

fn validate_scope(value: &str) -> Result<(), CryptoError> {
    if value.is_empty()
        || value.len() > MAX_SCOPE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(CryptoError::new(CryptoErrorCode::InvalidMetadata))
    } else {
        Ok(())
    }
}

fn generate_material(
    algorithm: KeyAlgorithm,
) -> Result<(SecretBytes, Option<[u8; ED25519_PUBLIC_BYTES]>), CryptoError> {
    match algorithm {
        KeyAlgorithm::Ed25519 => {
            let secret = generate_ed25519_secret()?;
            let public = ed25519_public_key(&secret)?;
            Ok((secret, Some(public)))
        }
        KeyAlgorithm::XChaCha20Poly1305 => Ok((generate_xchacha20_key()?, None)),
    }
}

fn unique_key_ref(keys: &BTreeMap<KeyRef, StoredKey>) -> Result<KeyRef, CryptoError> {
    for _attempt in 0..KEY_REFERENCE_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
        let mut value = String::from("key-");
        for byte in bytes {
            use std::fmt::Write as _;
            let _result = write!(&mut value, "{byte:02x}");
        }
        let key_ref = KeyRef::new(value)?;
        if !keys.contains_key(&key_ref) {
            return Ok(key_ref);
        }
    }
    Err(CryptoError::new(CryptoErrorCode::ProviderUnavailable))
}

fn scoped_key<'a>(
    keys: &'a BTreeMap<KeyRef, StoredKey>,
    key_ref: &KeyRef,
    tenant: &str,
) -> Result<&'a StoredKey, CryptoError> {
    let stored = keys
        .get(key_ref)
        .ok_or_else(|| CryptoError::new(CryptoErrorCode::UnknownKey))?;
    if stored.metadata.tenant != tenant {
        return Err(CryptoError::new(CryptoErrorCode::ScopeDenied));
    }
    Ok(stored)
}

fn scoped_key_mut<'a>(
    keys: &'a mut BTreeMap<KeyRef, StoredKey>,
    key_ref: &KeyRef,
    tenant: &str,
) -> Result<&'a mut StoredKey, CryptoError> {
    let stored = keys
        .get_mut(key_ref)
        .ok_or_else(|| CryptoError::new(CryptoErrorCode::UnknownKey))?;
    if stored.metadata.tenant != tenant {
        return Err(CryptoError::new(CryptoErrorCode::ScopeDenied));
    }
    Ok(stored)
}

fn require_usable(stored: &StoredKey, purpose: KeyPurpose, at: i128) -> Result<(), CryptoError> {
    if stored.metadata.purpose != purpose {
        return Err(CryptoError::new(CryptoErrorCode::ScopeDenied));
    }
    if stored.metadata.status != KeyStatus::Active
        || at < stored.metadata.activated_at
        || stored
            .metadata
            .deactivated_at
            .is_some_and(|time| at >= time)
        || stored.material.is_none()
    {
        return Err(CryptoError::new(CryptoErrorCode::KeyInactive));
    }
    Ok(())
}

fn require_decryptable(
    stored: &StoredKey,
    purpose: KeyPurpose,
    at: i128,
) -> Result<(), CryptoError> {
    if stored.metadata.purpose != purpose {
        return Err(CryptoError::new(CryptoErrorCode::ScopeDenied));
    }
    if !matches!(
        stored.metadata.status,
        KeyStatus::Active | KeyStatus::Retired
    ) || at < stored.metadata.activated_at
        || stored.material.is_none()
    {
        return Err(CryptoError::new(CryptoErrorCode::KeyInactive));
    }
    Ok(())
}

fn signature_input(envelope: &SignatureEnvelope) -> Result<Vec<u8>, CryptoError> {
    let mut values = BTreeMap::new();
    values.insert(
        "algorithm".to_owned(),
        CanonicalNode::Text("ed25519".to_owned()),
    );
    values.insert(
        "key_ref".to_owned(),
        CanonicalNode::Text(envelope.key_ref.as_str().to_owned()),
    );
    values.insert(
        "payload_digest".to_owned(),
        CanonicalNode::Bytes(envelope.payload_digest.to_vec()),
    );
    values.insert(
        "purpose".to_owned(),
        CanonicalNode::Text(envelope.purpose.clone()),
    );
    values.insert(
        "signed_at".to_owned(),
        canonical_integer(envelope.signed_at)?,
    );
    values.insert(
        "signer".to_owned(),
        CanonicalNode::Text(envelope.signer.clone()),
    );
    if let Some(expires_at) = envelope.expires_at {
        values.insert("expires_at".to_owned(), canonical_integer(expires_at)?);
    }
    let canonical = to_deterministic_cbor(&CanonicalNode::Map(values))
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
    let mut framed = b"CIGAR-SIGNATURE\0v1\0".to_vec();
    framed.extend_from_slice(&canonical);
    Ok(framed)
}

fn canonical_integer(value: i128) -> Result<CanonicalNode, CryptoError> {
    if value < 0 {
        i64::try_from(value)
            .map(CanonicalNode::Negative)
            .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))
    } else {
        u64::try_from(value)
            .map(CanonicalNode::Unsigned)
            .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreateKeyRequest, ImmutableKeyProvider, KeyAlgorithm, KeyProvider, KeyPurpose, KeyStatus,
        MemoryKeyProvider, SignatureRequest, SignatureVerification,
    };
    use crate::{CryptoErrorCode, SecretBytes};
    use std::sync::Arc;

    fn signing_request() -> CreateKeyRequest {
        CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 10,
            activated_at: 20,
        }
    }

    #[test]
    fn immutable_wrapper_delegates_use_and_denies_every_lifecycle_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mutable = Arc::new(MemoryKeyProvider::default());
        let key = mutable.create(signing_request())?;
        let provider = ImmutableKeyProvider::new(mutable);
        assert!(
            provider
                .resolve(&key.key_ref, "tenant-a", KeyPurpose::Signing, 20)
                .is_ok()
        );
        let signature = provider.sign(SignatureRequest {
            key_ref: &key.key_ref,
            tenant: "tenant-a",
            signer: "principal-a",
            purpose: "immutable-test",
            payload_digest: [4; 32],
            signed_at: 20,
            expires_at: None,
        })?;
        provider.verify(
            &signature,
            SignatureVerification {
                tenant: "tenant-a",
                signer: "principal-a",
                purpose: "immutable-test",
                payload_digest: &[4; 32],
                now: 20,
            },
        )?;
        for error in [
            provider.create(signing_request()).err(),
            provider.rotate(&key.key_ref, "tenant-a", 30).err(),
            provider.destroy(&key.key_ref, "tenant-a", 30).err(),
        ] {
            assert_eq!(
                error
                    .ok_or("immutable mutation unexpectedly passed")?
                    .code(),
                CryptoErrorCode::ScopeDenied
            );
        }
        Ok(())
    }

    #[test]
    fn tenant_purpose_time_and_rotation_are_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let provider = MemoryKeyProvider::default();
        let first = provider.create(signing_request())?;
        assert_eq!(
            provider
                .resolve(&first.key_ref, "tenant-b", KeyPurpose::Signing, 20)
                .err()
                .ok_or("cross-tenant resolve unexpectedly passed")?
                .code(),
            CryptoErrorCode::ScopeDenied
        );
        assert_eq!(
            provider
                .resolve(&first.key_ref, "tenant-a", KeyPurpose::BlobEncryption, 20)
                .err()
                .ok_or("cross-purpose resolve unexpectedly passed")?
                .code(),
            CryptoErrorCode::ScopeDenied
        );
        let successor = provider.rotate(&first.key_ref, "tenant-a", 30)?;
        assert_eq!(successor.status, KeyStatus::Active);
        assert!(
            provider
                .resolve(&first.key_ref, "tenant-a", KeyPurpose::Signing, 30)
                .is_err()
        );
        assert!(
            provider
                .resolve(&successor.key_ref, "tenant-a", KeyPurpose::Signing, 30)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn signature_envelope_binds_scope_digest_time_and_historical_key_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = MemoryKeyProvider::default();
        let key = provider.create(signing_request())?;
        let digest = [7_u8; 32];
        let envelope = provider.sign(SignatureRequest {
            key_ref: &key.key_ref,
            tenant: "tenant-a",
            signer: "principal-a",
            purpose: "handoff",
            payload_digest: digest,
            signed_at: 25,
            expires_at: Some(40),
        })?;
        provider.rotate(&key.key_ref, "tenant-a", 30)?;
        provider.verify(
            &envelope,
            SignatureVerification {
                tenant: "tenant-a",
                signer: "principal-a",
                purpose: "handoff",
                payload_digest: &digest,
                now: 35,
            },
        )?;
        for expectation in [
            SignatureVerification {
                purpose: "effect",
                now: 35,
                tenant: "tenant-a",
                signer: "principal-a",
                payload_digest: &digest,
            },
            SignatureVerification {
                tenant: "tenant-b",
                now: 35,
                signer: "principal-a",
                purpose: "handoff",
                payload_digest: &digest,
            },
            SignatureVerification {
                now: 40,
                tenant: "tenant-a",
                signer: "principal-a",
                purpose: "handoff",
                payload_digest: &digest,
            },
        ] {
            assert!(provider.verify(&envelope, expectation).is_err());
        }
        let wrong_digest = [8_u8; 32];
        assert!(
            provider
                .verify(
                    &envelope,
                    SignatureVerification {
                        tenant: "tenant-a",
                        signer: "principal-a",
                        purpose: "handoff",
                        payload_digest: &wrong_digest,
                        now: 35,
                    }
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn wrapping_and_destroy_bind_tenant_aad_and_lifecycle() -> Result<(), Box<dyn std::error::Error>>
    {
        let provider = MemoryKeyProvider::default();
        let key = provider.create(CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 10,
            activated_at: 10,
        })?;
        let data_key = SecretBytes::new(vec![5; 32]);
        let wrapped = provider.wrap(&key.key_ref, "tenant-a", &data_key, b"blob-a", 10)?;
        let unwrapped = provider.unwrap(&key.key_ref, "tenant-a", &wrapped, b"blob-a", 10)?;
        assert_eq!(unwrapped.expose(), data_key.expose());
        assert!(
            provider
                .unwrap(&key.key_ref, "tenant-a", &wrapped, b"blob-b", 10)
                .is_err()
        );
        assert!(
            provider
                .unwrap(&key.key_ref, "tenant-b", &wrapped, b"blob-a", 10)
                .is_err()
        );
        let destroyed = provider.destroy(&key.key_ref, "tenant-a", 20)?;
        assert_eq!(destroyed.status, KeyStatus::Destroyed);
        assert!(
            provider
                .wrap(&key.key_ref, "tenant-a", &data_key, b"blob-a", 20)
                .is_err()
        );
        assert_eq!(format!("{provider:?}"), "MemoryKeyProvider([REDACTED])");
        Ok(())
    }
}
