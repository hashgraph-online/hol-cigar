//! Maintained platform credential stores behind the existing OS-keystore API.

use crate::{CryptoError, CryptoErrorCode, SecretBytes};
#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
use keyring_core::CredentialStore;
#[cfg(any(
    test,
    not(unix),
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
))]
use keyring_core::Entry;
#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
use std::sync::{Arc, LazyLock};

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
static STORE: LazyLock<keyring_core::Result<Arc<CredentialStore>>> =
    LazyLock::new(open_platform_store);

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
mod secret_service;

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
pub(super) fn load_or_create(service: &str, account: &str) -> Result<SecretBytes, CryptoError> {
    secret_service::load_or_create(service, account)
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
pub(super) fn load_or_create(service: &str, account: &str) -> Result<SecretBytes, CryptoError> {
    // Preserve the native macOS and Windows stores and credential namespace.
    // Do not replace or depend on another library's process-global default.
    let store = STORE
        .as_ref()
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    let entry = store
        .build(service, account, None)
        .map_err(|_error| CryptoError::new(CryptoErrorCode::ProviderUnavailable))?;
    secret_from_entry(&entry)
}

#[cfg(any(
    test,
    not(unix),
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
))]
fn secret_from_entry(entry: &Entry) -> Result<SecretBytes, CryptoError> {
    let secret = match entry.get_secret() {
        Ok(secret) => secret,
        Err(keyring_core::Error::NoEntry) => {
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
    Ok(SecretBytes::new(secret))
}

#[cfg(target_os = "macos")]
fn open_platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(target_os = "windows")]
fn open_platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

#[cfg(not(all(any(unix, windows), not(any(target_os = "ios", target_os = "android")))))]
fn open_platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Err(keyring_core::Error::NoDefaultStore)
}

#[cfg(test)]
mod tests {
    use super::secret_from_entry;
    use crate::CryptoErrorCode;
    use keyring_core::api::CredentialStoreApi;

    #[test]
    fn keychain_reuses_existing_secrets_and_keeps_service_account_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = keyring_core::mock::Store::new()?;
        let first = store.build("service", "account", None)?;
        let original = secret_from_entry(&first)?;
        let repeated = secret_from_entry(&store.build("service", "account", None)?)?;
        assert_eq!(original.expose().len(), 32);
        assert!(original.expose() == repeated.expose());
        assert!(
            original.expose()
                != secret_from_entry(&store.build("service", "other-account", None)?)?.expose()
        );
        assert!(
            original.expose()
                != secret_from_entry(&store.build("other-service", "account", None)?)?.expose()
        );
        Ok(())
    }

    #[test]
    fn keychain_rejects_wrong_sized_existing_secret_without_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = keyring_core::mock::Store::new()?;
        let entry = store.build("service", "account", None)?;
        entry.set_secret(&[7; 31])?;
        assert!(matches!(
            secret_from_entry(&entry),
            Err(error) if error.code() == CryptoErrorCode::InvalidKey
        ));
        assert!(entry.get_secret()? == [7; 31]);
        Ok(())
    }

    #[test]
    fn keychain_read_error_never_creates_a_replacement_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let credential = std::sync::Arc::new(keyring_core::mock::Cred {
            specifiers: ("service".to_owned(), "account".to_owned()),
            inner: std::sync::Mutex::new(std::cell::RefCell::new(keyring_core::mock::CredData {
                secret: None,
                error: Some(keyring_core::Error::NoDefaultStore),
            })),
        });
        let entry = keyring_core::Entry::new_with_credential(credential.clone());
        assert!(matches!(
            secret_from_entry(&entry),
            Err(error) if error.code() == CryptoErrorCode::ProviderUnavailable
        ));
        assert!(matches!(
            entry.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
        Ok(())
    }

    /// Run only inside the fresh D-Bus session and private keyring created by CI.
    /// libsecret seeds the attributes used by the previous zbus provider, so this
    /// exercises migration of an existing credential rather than a new-store round trip.
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    #[test]
    #[ignore = "requires an explicitly isolated Secret Service session"]
    fn linux_secret_service_reuses_legacy_credentials() -> Result<(), Box<dyn std::error::Error>> {
        use crate::{
            CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, OsKeychainKeyProvider,
            SecretBytes,
        };
        use std::io::Write;
        use std::process::{Command, Stdio};

        assert_eq!(
            std::env::var("CIGAR_ISOLATED_SECRET_SERVICE_TEST").as_deref(),
            Ok("1")
        );
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let service = format!("cigar-compatibility-{}", std::process::id());
        let account = "legacy-account";
        // Synthetic fixture only: never read or modify the user's live keychain.
        let original = b"0123456789abcdef0123456789abcdef";
        let mut writer = Command::new("secret-tool")
            .args([
                "store",
                "--label",
                &format!("keyring:{account}@{service}"),
                "service",
                &service,
                "username",
                account,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
        writer
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing fixture input"))?
            .write_all(original)?;
        assert!(writer.wait()?.success());
        assert!(super::load_or_create(&service, account)?.expose() == original);

        let path = root.join("keys.cigar");
        let (key, envelope) = {
            let provider = OsKeychainKeyProvider::open(&service, account, &path)?;
            let key = provider.create(CreateKeyRequest {
                tenant: "tenant-a".to_owned(),
                purpose: KeyPurpose::BlobEncryption,
                algorithm: KeyAlgorithm::XChaCha20Poly1305,
                created_at: 1,
                activated_at: 1,
            })?;
            let envelope = provider.wrap(
                &key.key_ref,
                "tenant-a",
                &SecretBytes::new(vec![3; 32]),
                b"blob",
                1,
            )?;
            (key, envelope)
        };
        let reopened = OsKeychainKeyProvider::open(&service, account, &path)?;
        assert!(
            reopened
                .unwrap(&key.key_ref, "tenant-a", &envelope, b"blob", 2)?
                .expose()
                == [3; 32]
        );
        assert!(super::load_or_create(&service, account)?.expose() == original);
        let fresh_account = "new-account";
        let fresh = super::load_or_create(&service, fresh_account)?;
        assert!(fresh.expose().len() == 32);
        assert!(fresh.expose() != original);
        assert!(fresh.expose() == super::load_or_create(&service, fresh_account)?.expose());

        let connection = ::secret_service::blocking::SecretService::connect(
            ::secret_service::EncryptionType::Dh,
        )?;
        let collection = connection.get_default_collection()?;
        let invalid = collection.create_item(
            "invalid-length fixture",
            std::collections::HashMap::from([
                ("service", service.as_str()),
                ("username", "invalid"),
            ]),
            &[7; 31],
            true,
            "application/octet-stream",
        )?;
        assert!(matches!(
            super::load_or_create(&service, "invalid"),
            Err(error) if error.code() == CryptoErrorCode::InvalidKey
        ));
        assert!(invalid.get_secret()? == [7; 31]);
        invalid.delete()?;

        let mut duplicates = Vec::new();
        for variant in ["one", "two"] {
            duplicates.push(collection.create_item(
                "ambiguous fixture",
                std::collections::HashMap::from([
                    ("service", service.as_str()),
                    ("username", "ambiguous"),
                    ("variant", variant),
                ]),
                original,
                false,
                "application/octet-stream",
            )?);
        }
        assert!(matches!(
            super::load_or_create(&service, "ambiguous"),
            Err(error) if error.code() == CryptoErrorCode::ProviderUnavailable
        ));
        for duplicate in duplicates {
            assert!(duplicate.get_secret()? == original);
            duplicate.delete()?;
        }
        assert!(
            Command::new("secret-tool")
                .args(["clear", "service", &service])
                .status()?
                .success()
        );
        Ok(())
    }
}
