//! Key abstractions, authenticated encryption, signatures, and secret-safe values.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;
use zeroize::Zeroize;

mod keystore;
mod provider;
mod uuid_v7;

pub use keystore::{EncryptedDevelopmentKeystore, KeystoreFailpoint, OsKeychainKeyProvider};
pub use provider::{
    CreateKeyRequest, ImmutableKeyProvider, KeyAlgorithm, KeyMetadata, KeyProvider, KeyPurpose,
    KeyRef, KeyStatus, MemoryKeyProvider, SignatureEnvelope, SignatureRequest,
    SignatureVerification,
};
pub use uuid_v7::{MonotonicUuidV7Generator, UuidV7};

/// XChaCha20-Poly1305 key bytes.
pub const XCHACHA20_KEY_BYTES: usize = 32;
/// XChaCha20-Poly1305 nonce bytes.
pub const XCHACHA20_NONCE_BYTES: usize = 24;
/// Ed25519 private seed bytes.
pub const ED25519_SECRET_BYTES: usize = 32;
/// Ed25519 public key bytes.
pub const ED25519_PUBLIC_BYTES: usize = 32;
/// Ed25519 signature bytes.
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// Stable cryptographic failure categories that never contain secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoErrorCode {
    /// Key material has the wrong size or form.
    InvalidKey,
    /// Nonce material has the wrong size or form.
    InvalidNonce,
    /// Authenticated encryption or decryption failed.
    AuthenticationFailed,
    /// Signature bytes, public key, or signature verification failed.
    SignatureInvalid,
    /// Operating-system randomness was unavailable.
    RandomUnavailable,
    /// Key reference is unknown without disclosing other tenant state.
    UnknownKey,
    /// Tenant, purpose, principal, or operation scope does not authorize key use.
    ScopeDenied,
    /// Key is not active at the requested semantic time.
    KeyInactive,
    /// Key metadata, algorithm, or requested lifecycle transition is invalid.
    InvalidMetadata,
    /// Signature envelope is expired or not yet temporally valid.
    SignatureExpired,
    /// Provider state could not be read or updated safely.
    ProviderUnavailable,
    /// UUIDv7 monotonic sequence space was exhausted for one retained millisecond.
    IdExhausted,
}

/// Content-free cryptographic error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CryptoError {
    code: CryptoErrorCode,
}

impl CryptoError {
    const fn new(code: CryptoErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(self) -> CryptoErrorCode {
        self.code
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CryptoError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cryptographic operation failed: {:?}", self.code)
    }
}

impl std::error::Error for CryptoError {}

/// Zeroizing secret bytes with permanently redacted formatting and no clone implementation.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the secret byte length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Zeroizing UTF-8 secret with permanently redacted formatting and no clone implementation.
pub struct SecretString(String);

impl SecretString {
    /// Takes ownership of a secret string.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the secret byte length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// Zeroizing provider/environment secret locator with redacted formatting.
pub struct SecretHandle(String);

impl SecretHandle {
    /// Validates and takes ownership of a secret locator.
    pub fn new(value: String) -> Result<Self, CryptoError> {
        let valid = !value.is_empty()
            && value.len() <= 4_096
            && value.contains(':')
            && !value.bytes().any(|byte| byte.is_ascii_control());
        if valid {
            Ok(Self(value))
        } else {
            Err(CryptoError::new(CryptoErrorCode::InvalidMetadata))
        }
    }

    /// Exposes the locator to the configuration/provider boundary, never to formatting.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHandle([REDACTED])")
    }
}

/// Authenticated XChaCha20-Poly1305 ciphertext and its unique nonce.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedEnvelope {
    nonce: [u8; XCHACHA20_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Reconstructs an envelope from persisted nonce and authenticated ciphertext.
    pub fn from_parts(
        nonce: [u8; XCHACHA20_NONCE_BYTES],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        Ok(Self { nonce, ciphertext })
    }

    /// Returns the public nonce bytes.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; XCHACHA20_NONCE_BYTES] {
        &self.nonce
    }

    /// Returns the authenticated ciphertext bytes, including the Poly1305 tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedEnvelope")
            .field("nonce_bytes", &self.nonce.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

/// Encrypts plaintext with a fresh 192-bit nonce and exact associated data.
pub fn encrypt_xchacha20(
    key: &SecretBytes,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    let mut nonce = [0_u8; XCHACHA20_NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
    encrypt_xchacha20_with_nonce(key, nonce, plaintext, associated_data)
}

/// Generates a fresh XChaCha20-Poly1305 secret key from the operating-system source.
pub fn generate_xchacha20_key() -> Result<SecretBytes, CryptoError> {
    let mut bytes = [0_u8; XCHACHA20_KEY_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
    Ok(SecretBytes::new(bytes.to_vec()))
}

fn encrypt_xchacha20_with_nonce(
    key: &SecretBytes,
    nonce: [u8; XCHACHA20_NONCE_BYTES],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidKey))?;
    let cipher_nonce = XNonce::try_from(nonce.as_slice())
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidNonce))?;
    let ciphertext = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_error| CryptoError::new(CryptoErrorCode::AuthenticationFailed))?;
    Ok(EncryptedEnvelope { nonce, ciphertext })
}

/// Decrypts only when key, nonce, ciphertext, and associated data authenticate exactly.
pub fn decrypt_xchacha20(
    key: &SecretBytes,
    envelope: &EncryptedEnvelope,
    associated_data: &[u8],
) -> Result<SecretBytes, CryptoError> {
    decrypt_xchacha20_bytes(key, envelope, associated_data).map(SecretBytes::new)
}

/// Decrypts authenticated protected content into caller-owned bytes without exposing key bytes.
pub fn decrypt_xchacha20_bytes(
    key: &SecretBytes,
    envelope: &EncryptedEnvelope,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidKey))?;
    let cipher_nonce = XNonce::try_from(envelope.nonce.as_slice())
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidNonce))?;
    let plaintext = cipher
        .decrypt(
            &cipher_nonce,
            Payload {
                msg: &envelope.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_error| CryptoError::new(CryptoErrorCode::AuthenticationFailed))?;
    Ok(plaintext)
}

/// Generates a new Ed25519 signing seed from the operating-system random source.
pub fn generate_ed25519_secret() -> Result<SecretBytes, CryptoError> {
    let mut secret = [0_u8; ED25519_SECRET_BYTES];
    getrandom::fill(&mut secret)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
    Ok(SecretBytes::new(secret.to_vec()))
}

fn signing_key(secret: &SecretBytes) -> Result<SigningKey, CryptoError> {
    let bytes: &[u8; ED25519_SECRET_BYTES] = secret
        .expose()
        .try_into()
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidKey))?;
    Ok(SigningKey::from_bytes(bytes))
}

/// Derives the Ed25519 public key for a private seed.
pub fn ed25519_public_key(secret: &SecretBytes) -> Result<[u8; ED25519_PUBLIC_BYTES], CryptoError> {
    Ok(signing_key(secret)?.verifying_key().to_bytes())
}

/// Signs an already-domain-separated semantic message.
pub fn sign_ed25519(
    secret: &SecretBytes,
    message: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_BYTES], CryptoError> {
    Ok(signing_key(secret)?.sign(message).to_bytes())
}

/// Verifies an Ed25519 signature over an exact domain-separated semantic message.
pub fn verify_ed25519(
    public_key: &[u8; ED25519_PUBLIC_BYTES],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_BYTES],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::SignatureInvalid))?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(message, &signature)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::SignatureInvalid))
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoErrorCode, SecretBytes, SecretHandle, SecretString, decrypt_xchacha20,
        ed25519_public_key, encrypt_xchacha20_with_nonce, sign_ed25519, verify_ed25519,
    };

    fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        if value.len() != N * 2 {
            return Err("hex fixture length mismatch".into());
        }
        let mut bytes = [0_u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            let end = start + 2;
            let pair = value.get(start..end).ok_or("hex fixture bounds")?;
            *byte = u8::from_str_radix(pair, 16)?;
        }
        Ok(bytes)
    }

    #[test]
    fn secrets_are_non_clone_and_debug_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = SecretBytes::new(b"secret-canary".to_vec());
        let string = SecretString::new("secret-canary".to_owned());
        let handle = SecretHandle::new("env:secret-canary".to_owned())?;
        assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
        assert_eq!(format!("{string:?}"), "SecretString([REDACTED])");
        assert_eq!(format!("{handle:?}"), "SecretHandle([REDACTED])");
        assert!(!format!("{bytes:?}{string:?}{handle:?}").contains("canary"));
        Ok(())
    }

    #[test]
    fn xchacha_round_trip_binds_key_nonce_ciphertext_and_aad()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = SecretBytes::new(vec![7; 32]);
        let envelope = encrypt_xchacha20_with_nonce(&key, [9; 24], b"plaintext", b"tenant-a")?;
        let plaintext = decrypt_xchacha20(&key, &envelope, b"tenant-a")?;
        assert_eq!(plaintext.expose(), b"plaintext");
        let error = decrypt_xchacha20(&key, &envelope, b"tenant-b");
        assert_eq!(
            error
                .err()
                .ok_or("wrong AAD unexpectedly authenticated")?
                .code(),
            CryptoErrorCode::AuthenticationFailed
        );
        let wrong_key = SecretBytes::new(vec![8; 32]);
        assert_eq!(
            decrypt_xchacha20(&wrong_key, &envelope, b"tenant-a")
                .err()
                .ok_or("wrong key unexpectedly authenticated")?
                .code(),
            CryptoErrorCode::AuthenticationFailed
        );
        let mut corrupted = envelope.clone();
        let first = corrupted
            .ciphertext
            .first_mut()
            .ok_or("ciphertext unexpectedly empty")?;
        *first ^= 1;
        assert_eq!(
            decrypt_xchacha20(&key, &corrupted, b"tenant-a")
                .err()
                .ok_or("corrupted ciphertext unexpectedly authenticated")?
                .code(),
            CryptoErrorCode::AuthenticationFailed
        );
        Ok(())
    }

    #[test]
    fn ed25519_matches_rfc8032_empty_message_vector() -> Result<(), Box<dyn std::error::Error>> {
        let secret = SecretBytes::new(
            decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?
                .to_vec(),
        );
        let expected_public =
            decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
        let expected_signature = decode_hex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                .replace([' ', '\n'], "")
                .as_str(),
        )?;
        assert_eq!(ed25519_public_key(&secret)?, expected_public);
        let signature = sign_ed25519(&secret, b"")?;
        assert_eq!(signature, expected_signature);
        verify_ed25519(&expected_public, b"", &signature)?;
        assert!(verify_ed25519(&expected_public, b"tampered", &signature).is_err());
        Ok(())
    }
}
