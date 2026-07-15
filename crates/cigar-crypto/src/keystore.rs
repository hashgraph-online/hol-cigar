//! Encrypted development keystore and operating-system keychain composition.

use crate::provider::{
    CreateKeyRequest, KeyMetadata, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
    SignatureEnvelope, SignatureRequest, SignatureVerification, StoredKey,
};
use crate::{
    CryptoError, CryptoErrorCode, EncryptedEnvelope, SecretBytes, decrypt_xchacha20_bytes,
    encrypt_xchacha20,
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

const KEYSTORE_MAGIC: &[u8; 16] = b"CIGAR-KEYS-v1\0\0\0";
const KEYSTORE_SALT_BYTES: usize = 16;
const MAX_KEYSTORE_BYTES: u64 = 16_777_216;
const MIN_PASSPHRASE_BYTES: usize = 16;

/// Named one-shot encrypted-keystore durability boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KeystoreFailpoint {
    /// After creating the same-directory temporary file.
    AfterTemporaryCreate,
    /// After writing all encrypted bytes.
    AfterTemporaryWrite,
    /// After synchronizing temporary-file data and metadata.
    AfterFileSync,
    /// After atomic replacement but before parent-directory synchronization.
    AfterRename,
    /// After parent-directory synchronization.
    AfterDirectorySync,
}

/// File-backed provider whose complete private state is Argon2id-derived and AEAD-encrypted.
pub struct EncryptedDevelopmentKeystore {
    path: PathBuf,
    passphrase: SecretBytes,
    salt: [u8; KEYSTORE_SALT_BYTES],
    inner: MemoryKeyProvider,
    mutation: Mutex<()>,
    failpoints: Mutex<BTreeSet<KeystoreFailpoint>>,
}

impl fmt::Debug for EncryptedDevelopmentKeystore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedDevelopmentKeystore([REDACTED])")
    }
}

impl EncryptedDevelopmentKeystore {
    /// Opens or atomically creates an encrypted keystore using a high-entropy passphrase.
    pub fn open(path: impl AsRef<Path>, passphrase: SecretBytes) -> Result<Self, CryptoError> {
        if passphrase.len() < MIN_PASSPHRASE_BYTES {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
        fs::create_dir_all(parent).map_err(provider_io)?;
        let (salt, inner) = if path.exists() {
            read_keystore(&path, &passphrase)?
        } else {
            let mut salt = [0_u8; KEYSTORE_SALT_BYTES];
            getrandom::fill(&mut salt)
                .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
            (salt, MemoryKeyProvider::default())
        };
        let store = Self {
            path,
            passphrase,
            salt,
            inner,
            mutation: Mutex::new(()),
            failpoints: Mutex::new(BTreeSet::new()),
        };
        if !store.path.exists() {
            store.persist_current().map_err(|failure| failure.error)?;
        }
        Ok(store)
    }

    /// Opens an existing encrypted keystore from bytes already read through a validated descriptor.
    ///
    /// This entry point is for service bootstraps that must bind ownership, link count, mode, and
    /// file identity to the same descriptor used for the read. The path is retained only as the
    /// durability destination; callers must not expose a mutable provider when the source mount is
    /// required to remain immutable.
    pub fn open_existing_bytes(
        path: impl AsRef<Path>,
        passphrase: SecretBytes,
        encoded: &[u8],
    ) -> Result<Self, CryptoError> {
        if passphrase.len() < MIN_PASSPHRASE_BYTES || encoded.len() > MAX_KEYSTORE_BYTES as usize {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        let path = path.as_ref().to_path_buf();
        if path.parent().is_none() {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
        let (salt, inner) = decode_keystore(encoded, &passphrase)?;
        Ok(Self {
            path,
            passphrase,
            salt,
            inner,
            mutation: Mutex::new(()),
            failpoints: Mutex::new(BTreeSet::new()),
        })
    }

    /// Arms one named one-shot durability failpoint.
    pub fn inject_failpoint(&self, failpoint: KeystoreFailpoint) -> Result<(), CryptoError> {
        self.failpoints
            .lock()
            .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?
            .insert(failpoint);
        Ok(())
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&MemoryKeyProvider) -> Result<T, CryptoError>,
    ) -> Result<T, CryptoError> {
        let _mutation = self.lock_mutation()?;
        let mut before = encode_provider(&self.inner)?;
        let result = match operation(&self.inner) {
            Ok(result) => result,
            Err(error) => {
                before.zeroize();
                return Err(error);
            }
        };
        if let Err(failure) = self.persist_current() {
            if !failure.published {
                let restore = decode_provider(&before);
                before.zeroize();
                let restored = restore?;
                *self.inner.lock()? = restored;
            } else {
                before.zeroize();
            }
            return Err(failure.error);
        }
        before.zeroize();
        Ok(result)
    }

    fn persist_current(&self) -> Result<(), PersistFailure> {
        let mut plaintext = encode_provider(&self.inner).map_err(PersistFailure::before)?;
        let key = derive_key(&self.passphrase, &self.salt).map_err(PersistFailure::before)?;
        let envelope = encrypt_xchacha20(&key, &plaintext, &keystore_aad(&self.salt))
            .map_err(PersistFailure::before)?;
        plaintext.zeroize();
        let framed = encode_file(&self.salt, &envelope).map_err(PersistFailure::before)?;
        let parent = self.path.parent().ok_or_else(|| {
            PersistFailure::before(CryptoError::new(CryptoErrorCode::InvalidMetadata))
        })?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".cigar-keystore-")
            .tempfile_in(parent)
            .map_err(|error| PersistFailure::before(provider_io(error)))?;
        restrict_file_permissions(temporary.as_file()).map_err(PersistFailure::before)?;
        self.trip(KeystoreFailpoint::AfterTemporaryCreate, false)?;
        temporary
            .write_all(&framed)
            .map_err(|error| PersistFailure::before(provider_io(error)))?;
        temporary
            .flush()
            .map_err(|error| PersistFailure::before(provider_io(error)))?;
        self.trip(KeystoreFailpoint::AfterTemporaryWrite, false)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| PersistFailure::before(provider_io(error)))?;
        self.trip(KeystoreFailpoint::AfterFileSync, false)?;
        temporary
            .persist(&self.path)
            .map_err(|error| PersistFailure::before(provider_io(error.error)))?;
        self.trip(KeystoreFailpoint::AfterRename, true)?;
        sync_directory(parent).map_err(PersistFailure::after)?;
        self.trip(KeystoreFailpoint::AfterDirectorySync, true)?;
        Ok(())
    }

    fn trip(&self, failpoint: KeystoreFailpoint, published: bool) -> Result<(), PersistFailure> {
        let mut failpoints = self.failpoints.lock().map_err(|_error| {
            PersistFailure::before(CryptoError::new(CryptoErrorCode::ProviderUnavailable))
        })?;
        if failpoints.remove(&failpoint) {
            Err(PersistFailure {
                error: CryptoError::new(CryptoErrorCode::ProviderUnavailable),
                published,
            })
        } else {
            Ok(())
        }
    }

    fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, CryptoError> {
        self.mutation
            .lock()
            .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))
    }
}

impl KeyProvider for EncryptedDevelopmentKeystore {
    fn create(&self, request: CreateKeyRequest) -> Result<KeyMetadata, CryptoError> {
        self.mutate(|provider| provider.create(request))
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
        key_ref: &KeyRef,
        tenant: &str,
        activated_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        self.mutate(|provider| provider.rotate(key_ref, tenant, activated_at))
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
        key_ref: &KeyRef,
        tenant: &str,
        destroyed_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        self.mutate(|provider| provider.destroy(key_ref, tenant, destroyed_at))
    }
}

/// Production provider using the native OS credential store to protect a file-keystore key.
pub struct OsKeychainKeyProvider {
    inner: EncryptedDevelopmentKeystore,
}

impl fmt::Debug for OsKeychainKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsKeychainKeyProvider([REDACTED])")
    }
}

impl OsKeychainKeyProvider {
    /// Opens a key provider whose random keystore key resides in the platform keychain.
    pub fn open(service: &str, account: &str, path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        validate_keychain_selector(service)?;
        validate_keychain_selector(account)?;
        let entry = keyring::Entry::new(service, account)
            .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
        let secret = match entry.get_secret() {
            Ok(secret) => secret,
            Err(keyring::Error::NoEntry) => {
                let mut secret = vec![0_u8; 32];
                getrandom::fill(&mut secret)
                    .map_err(|_error| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
                entry
                    .set_secret(&secret)
                    .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
                secret
            }
            Err(_error) => return Err(CryptoError::new(CryptoErrorCode::ProviderUnavailable)),
        };
        if secret.len() != 32 {
            return Err(CryptoError::new(CryptoErrorCode::InvalidKey));
        }
        Ok(Self {
            inner: EncryptedDevelopmentKeystore::open(path, SecretBytes::new(secret))?,
        })
    }
}

impl KeyProvider for OsKeychainKeyProvider {
    fn create(&self, request: CreateKeyRequest) -> Result<KeyMetadata, CryptoError> {
        self.inner.create(request)
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
        key_ref: &KeyRef,
        tenant: &str,
        activated_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        self.inner.rotate(key_ref, tenant, activated_at)
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
        key_ref: &KeyRef,
        tenant: &str,
        destroyed_at: i128,
    ) -> Result<KeyMetadata, CryptoError> {
        self.inner.destroy(key_ref, tenant, destroyed_at)
    }
}

#[derive(Deserialize, Serialize)]
struct PersistedProvider {
    version: u8,
    keys: Vec<PersistedKey>,
}

#[derive(Deserialize, Serialize)]
struct PersistedKey {
    metadata: KeyMetadata,
    material: Option<Vec<u8>>,
}

struct PersistFailure {
    error: CryptoError,
    published: bool,
}

impl PersistFailure {
    const fn before(error: CryptoError) -> Self {
        Self {
            error,
            published: false,
        }
    }

    const fn after(error: CryptoError) -> Self {
        Self {
            error,
            published: true,
        }
    }
}

fn encode_provider(provider: &MemoryKeyProvider) -> Result<Vec<u8>, CryptoError> {
    let keys = provider.lock()?;
    let persisted = PersistedProvider {
        version: 1,
        keys: keys
            .values()
            .map(|stored| PersistedKey {
                metadata: stored.metadata.clone(),
                material: stored
                    .material
                    .as_ref()
                    .map(|material| material.expose().to_vec()),
            })
            .collect(),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&persisted, &mut bytes)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    Ok(bytes)
}

fn decode_provider(bytes: &[u8]) -> Result<BTreeMap<KeyRef, StoredKey>, CryptoError> {
    let persisted: PersistedProvider = ciborium::de::from_reader(bytes)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    if persisted.version != 1 || persisted.keys.len() > 100_000 {
        return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
    }
    let mut keys = BTreeMap::new();
    for key in persisted.keys {
        let reference = key.metadata.key_ref.clone();
        if keys
            .insert(
                reference,
                StoredKey {
                    metadata: key.metadata,
                    material: key.material.map(SecretBytes::new),
                },
            )
            .is_some()
        {
            return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
        }
    }
    Ok(keys)
}

fn read_keystore(
    path: &Path,
    passphrase: &SecretBytes,
) -> Result<([u8; KEYSTORE_SALT_BYTES], MemoryKeyProvider), CryptoError> {
    let mut file = open_bounded_read(path).map_err(provider_io)?;
    let length = file.metadata().map_err(provider_io)?.len();
    if length > MAX_KEYSTORE_BYTES {
        return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
    }
    let capacity = usize::try_from(length)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes).map_err(provider_io)?;
    decode_keystore(&bytes, passphrase)
}

fn decode_keystore(
    bytes: &[u8],
    passphrase: &SecretBytes,
) -> Result<([u8; KEYSTORE_SALT_BYTES], MemoryKeyProvider), CryptoError> {
    let (salt, envelope) = decode_file(bytes)?;
    let key = derive_key(passphrase, &salt)?;
    let mut plaintext = decrypt_xchacha20_bytes(&key, &envelope, &keystore_aad(&salt))?;
    let keys = decode_provider(&plaintext);
    plaintext.zeroize();
    Ok((
        salt,
        MemoryKeyProvider {
            keys: Mutex::new(keys?),
        },
    ))
}

#[cfg(unix)]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    open_bounded_read_before_final(path, || Ok(()))
}

#[cfg(unix)]
fn open_bounded_read_before_final(
    path: &Path,
    before_final: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() && !absolute => absolute = true,
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(invalid_read_path()),
        }
    }
    let (file_name, ancestors) = names.split_last().ok_or_else(invalid_read_path)?;
    let base = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = open(
        base,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)?;
    validate_read_ancestor(&directory.metadata()?)?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)?;
        validate_read_ancestor(&directory.metadata()?)?;
    }
    before_final()?;
    openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn validate_read_ancestor(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if metadata.is_dir()
        && (owner == 0 || owner == rustix::process::geteuid().as_raw())
        && (!writable_by_others || protected_sticky_root)
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe file ancestor",
        ))
    }
}

#[cfg(unix)]
fn invalid_read_path() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid file path")
}

#[cfg(not(unix))]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn derive_key(
    passphrase: &SecretBytes,
    salt: &[u8; KEYSTORE_SALT_BYTES],
) -> Result<SecretBytes, CryptoError> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0_u8; 32];
    argon
        .hash_password_into(passphrase.expose(), salt, &mut key)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    Ok(SecretBytes::new(key))
}

fn encode_file(
    salt: &[u8; KEYSTORE_SALT_BYTES],
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>, CryptoError> {
    let length = u32::try_from(envelope.ciphertext().len())
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(KEYSTORE_MAGIC);
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(envelope.nonce());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(envelope.ciphertext());
    Ok(bytes)
}

fn decode_file(
    bytes: &[u8],
) -> Result<([u8; KEYSTORE_SALT_BYTES], EncryptedEnvelope), CryptoError> {
    let header = KEYSTORE_MAGIC.len() + KEYSTORE_SALT_BYTES + 24 + 4;
    if bytes.len() < header || bytes.get(..KEYSTORE_MAGIC.len()) != Some(KEYSTORE_MAGIC) {
        return Err(CryptoError::new(CryptoErrorCode::InvalidMetadata));
    }
    let salt_start = KEYSTORE_MAGIC.len();
    let salt_end = salt_start + KEYSTORE_SALT_BYTES;
    let nonce_end = salt_end + 24;
    let length_end = nonce_end + 4;
    let salt: [u8; KEYSTORE_SALT_BYTES] = bytes
        .get(salt_start..salt_end)
        .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?
        .try_into()
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
    let nonce: [u8; 24] = bytes
        .get(salt_end..nonce_end)
        .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?
        .try_into()
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
    let length = u32::from_be_bytes(
        bytes
            .get(nonce_end..length_end)
            .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?
            .try_into()
            .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?,
    );
    let length = usize::try_from(length)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::InvalidMetadata))?;
    let ciphertext = bytes
        .get(length_end..)
        .filter(|ciphertext| ciphertext.len() == length)
        .ok_or_else(|| CryptoError::new(CryptoErrorCode::InvalidMetadata))?
        .to_vec();
    Ok((salt, EncryptedEnvelope::from_parts(nonce, ciphertext)?))
}

fn keystore_aad(salt: &[u8; KEYSTORE_SALT_BYTES]) -> Vec<u8> {
    let mut bytes = b"CIGAR-KEYSTORE-AAD\0v1\0".to_vec();
    bytes.extend_from_slice(salt);
    bytes
}

fn validate_keychain_selector(value: &str) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        Err(CryptoError::new(CryptoErrorCode::InvalidMetadata))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_file_permissions(file: &File) -> Result<(), CryptoError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(provider_io)
}

#[cfg(not(unix))]
fn restrict_file_permissions(_file: &File) -> Result<(), CryptoError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), CryptoError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(provider_io)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), CryptoError> {
    Ok(())
}

fn provider_io(_error: std::io::Error) -> CryptoError {
    CryptoError::new(CryptoErrorCode::ProviderUnavailable)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::open_bounded_read_before_final;
    use super::{EncryptedDevelopmentKeystore, KeystoreFailpoint};
    use crate::{
        CreateKeyRequest, CryptoErrorCode, KeyAlgorithm, KeyProvider, KeyPurpose, SecretBytes,
    };

    fn request() -> CreateKeyRequest {
        CreateKeyRequest {
            tenant: "tenant-a".to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        }
    }

    fn passphrase() -> SecretBytes {
        SecretBytes::new(b"development-passphrase-secret-canary".to_vec())
    }

    #[test]
    fn encrypted_keystore_persists_rotates_and_rejects_wrong_passphrase()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let path = root.join("keys.cigar");
        let first = {
            let store = EncryptedDevelopmentKeystore::open(&path, passphrase())?;
            let first = store.create(request())?;
            let data_key = SecretBytes::new(vec![3_u8; 32]);
            let envelope = store.wrap(&first.key_ref, "tenant-a", &data_key, b"blob", 1)?;
            let successor = store.rotate(&first.key_ref, "tenant-a", 2)?;
            store.unwrap(&first.key_ref, "tenant-a", &envelope, b"blob", 2)?;
            assert!(
                store
                    .wrap(&first.key_ref, "tenant-a", &data_key, b"new", 2)
                    .is_err()
            );
            assert!(
                store
                    .wrap(&successor.key_ref, "tenant-a", &data_key, b"new", 2)
                    .is_ok()
            );
            first
        };
        let persisted = std::fs::read(&path)?;
        assert!(
            !persisted
                .windows(13)
                .any(|window| window == b"secret-canary")
        );
        let reopened = EncryptedDevelopmentKeystore::open(&path, passphrase())?;
        assert!(
            reopened
                .resolve(&first.key_ref, "tenant-a", KeyPurpose::BlobEncryption, 2)
                .is_err()
        );
        let wrong = EncryptedDevelopmentKeystore::open(
            &path,
            SecretBytes::new(b"wrong-passphrase-with-enough-bytes".to_vec()),
        );
        assert!(matches!(
            wrong,
            Err(error) if error.code() == CryptoErrorCode::AuthenticationFailed
        ));
        Ok(())
    }

    #[test]
    fn keystore_failpoints_distinguish_pre_and_post_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let path = root.join("keys.cigar");
        let store = EncryptedDevelopmentKeystore::open(&path, passphrase())?;
        store.inject_failpoint(KeystoreFailpoint::AfterFileSync)?;
        assert_eq!(
            store.create(request()).map_err(|error| error.code()),
            Err(CryptoErrorCode::ProviderUnavailable)
        );
        assert!(store.inner.lock()?.is_empty());
        store.inject_failpoint(KeystoreFailpoint::AfterRename)?;
        assert_eq!(
            store.create(request()).map_err(|error| error.code()),
            Err(CryptoErrorCode::ProviderUnavailable)
        );
        assert_eq!(store.inner.lock()?.len(), 1);
        drop(store);
        let reopened = EncryptedDevelopmentKeystore::open(&path, passphrase())?;
        assert_eq!(reopened.inner.lock()?.len(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn keystore_reads_reject_symlinked_ancestors_and_pin_open_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let trusted = root.join("trusted");
        let replacement = root.join("replacement");
        std::fs::create_dir(&trusted)?;
        std::fs::create_dir(&replacement)?;
        std::fs::write(trusted.join("value"), b"trusted")?;
        std::fs::write(replacement.join("value"), b"substituted")?;

        let alias = root.join("alias");
        symlink(&trusted, &alias)?;
        assert!(open_bounded_read_before_final(&alias.join("value"), || Ok(())).is_err());

        let moved = root.join("moved");
        let requested = trusted.join("value");
        let mut opened = open_bounded_read_before_final(&requested, || {
            std::fs::rename(&trusted, &moved)?;
            std::fs::rename(&replacement, &trusted)?;
            Ok(())
        })?;
        let mut value = String::new();
        opened.read_to_string(&mut value)?;
        assert_eq!(value, "trusted");
        assert_eq!(std::fs::read_to_string(&requested)?, "substituted");
        Ok(())
    }
}
