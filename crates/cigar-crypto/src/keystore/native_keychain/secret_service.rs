//! The existing encrypted Secret Service protocol on the maintained zbus 6 line.

use crate::{CryptoError, CryptoErrorCode, SecretBytes};
use ::secret_service::{EncryptionType, blocking::SecretService};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

static SERVICE: LazyLock<Result<Mutex<SecretService<'static>>, CryptoError>> =
    LazyLock::new(|| {
        SecretService::connect(EncryptionType::Dh)
            .map(Mutex::new)
            .map_err(unavailable)
    });

fn unavailable<T>(_error: T) -> CryptoError {
    CryptoError::new(CryptoErrorCode::ProviderUnavailable)
}

pub(super) fn load_or_create(service: &str, account: &str) -> Result<SecretBytes, CryptoError> {
    let service_connection = SERVICE.as_ref().map_err(unavailable)?;
    // Hold the connection lock across lookup and creation, including unlocks.
    let connection = service_connection.lock().map_err(unavailable)?;
    let attributes = HashMap::from([("service", service), ("username", account)]);
    let found = connection
        .search_items(attributes.clone())
        .map_err(unavailable)?;
    // Ambiguous credentials and all transport/access failures fail closed.
    if found.unlocked.len() + found.locked.len() > 1 {
        return Err(unavailable(()));
    }
    let secret = if let Some(item) = found.unlocked.first().or_else(|| found.locked.first()) {
        if item.is_locked().map_err(unavailable)? {
            item.unlock().map_err(unavailable)?;
        }
        item.get_secret().map_err(unavailable)?
    } else {
        // Only a successful, empty search may create a new credential. Preserve
        // the default collection, legacy label and binary content type.
        let collection = connection.get_default_collection().map_err(unavailable)?;
        if collection.is_locked().map_err(unavailable)? {
            collection.unlock().map_err(unavailable)?;
        }
        let mut secret = vec![0; 32];
        getrandom::fill(&mut secret)
            .map_err(|_| CryptoError::new(CryptoErrorCode::RandomUnavailable))?;
        collection
            .create_item(
                &format!("keyring:{account}@{service}"),
                attributes,
                &secret,
                true,
                "application/octet-stream",
            )
            .map_err(unavailable)?;
        secret
    };
    if secret.len() != 32 {
        return Err(CryptoError::new(CryptoErrorCode::InvalidKey));
    }
    Ok(SecretBytes::new(secret))
}
