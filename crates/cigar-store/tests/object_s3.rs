//! Live S3-compatible encrypted CAS qualification against an explicit test endpoint.

use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider};
use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
use cigar_store::{
    BlobRecord, ObjectRepositoryBlobStore, ObjectStorage, ObjectStorageErrorCode,
    RepositoryBlobStore, S3CompatibleObjectStorage, restore_object_backup_inventory,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;

fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(ContentDigest::new(format!("1220{suffix}"))?)
}

#[test]
fn s3_conditional_encrypted_cas_missing_object_and_expired_credentials()
-> Result<(), Box<dyn Error>> {
    let endpoint = match std::env::var("CIGAR_TEST_S3_ENDPOINT") {
        Ok(value) => value,
        Err(_error) if std::env::var_os("CIGAR_REQUIRE_LIVE_SHARED_TESTS").is_none() => {
            return Ok(());
        }
        Err(_error) => return Err("required live S3 qualification was not configured".into()),
    };
    let access_key = std::env::var("CIGAR_TEST_S3_ACCESS_KEY")?;
    let secret_key = std::env::var("CIGAR_TEST_S3_SECRET_KEY")?;
    let admin_access_key = std::env::var("CIGAR_TEST_S3_ADMIN_ACCESS_KEY")?;
    let admin_secret_key = std::env::var("CIGAR_TEST_S3_ADMIN_SECRET_KEY")?;
    let bucket = std::env::var("CIGAR_TEST_S3_BUCKET")?;
    let prefix = format!("cigar-v1/wp18-live-{}/", std::process::id());
    let restored_prefix = format!("cigar-v1/wp18-live-{}-restore/", std::process::id());
    let storage = Arc::new(S3CompatibleObjectStorage::new(
        &endpoint,
        "us-east-1",
        &bucket,
        &prefix,
        &access_key,
        &secret_key,
        None,
        true,
    )?);
    let administrative_storage = S3CompatibleObjectStorage::new(
        &endpoint,
        "us-east-1",
        &bucket,
        &prefix,
        &admin_access_key,
        &admin_secret_key,
        None,
        true,
    )?;
    let provider = Arc::new(MemoryKeyProvider::default());
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?;
    let key = provider.create(CreateKeyRequest {
        tenant: tenant.as_str().to_owned(),
        purpose: KeyPurpose::BlobEncryption,
        algorithm: KeyAlgorithm::XChaCha20Poly1305,
        created_at: 1,
        activated_at: 1,
    })?;
    let adapter = ObjectRepositoryBlobStore::new(
        Arc::clone(&provider),
        Arc::clone(&storage),
        key.key_ref.clone(),
        1,
        [0x79; 32],
    );
    let plaintext = b"s3-secret-canary".to_vec();
    let blob = BlobRecord::new(
        BlobRef {
            digest: digest(&plaintext)?,
            size_bytes: u64::try_from(plaintext.len())?,
            media_type: MediaType::new("application/octet-stream")?,
        },
        plaintext,
    )?;
    adapter.put(&tenant, &blob)?;
    adapter.put(&tenant, &blob)?;
    assert_eq!(adapter.get(&tenant, &blob.reference)?, Some(blob.clone()));

    let keys = storage.list_prefix("tenants/", 100)?;
    let final_key = keys
        .iter()
        .find(|key| key.contains("/objects/"))
        .ok_or("missing committed S3 object")?;
    let protected = storage.get(final_key)?;
    assert!(
        !protected
            .windows(blob.bytes().len())
            .any(|window| window == blob.bytes())
    );

    assert_eq!(
        storage.delete(final_key).map_err(|error| error.code()),
        Err(ObjectStorageErrorCode::CredentialsExpired),
        "the runtime policy must deny deletion of committed ciphertext"
    );

    let live = BTreeMap::from([(
        tenant.as_str().to_owned(),
        BTreeSet::from([blob.reference.digest.clone()]),
    )]);
    let inventory = adapter.backup_inventory(&live)?;
    let restored_storage = Arc::new(S3CompatibleObjectStorage::new(
        &endpoint,
        "us-east-1",
        &bucket,
        &restored_prefix,
        &access_key,
        &secret_key,
        None,
        true,
    )?);
    let restored_administrative_storage = S3CompatibleObjectStorage::new(
        &endpoint,
        "us-east-1",
        &bucket,
        &restored_prefix,
        &admin_access_key,
        &admin_secret_key,
        None,
        true,
    )?;
    let receipt = restore_object_backup_inventory(
        &administrative_storage,
        &restored_administrative_storage,
        &inventory,
    )?;
    assert_eq!(receipt.object_count(), 1);
    assert_eq!(receipt.ciphertext_bytes(), u64::try_from(protected.len())?);
    assert_eq!(
        restored_administrative_storage.list_namespace(100)?,
        inventory
            .entries
            .iter()
            .map(|entry| entry.storage_key.clone())
            .collect::<Vec<_>>()
    );
    let restored_adapter = ObjectRepositoryBlobStore::new(
        Arc::clone(&provider),
        Arc::clone(&restored_storage),
        key.key_ref,
        1,
        [0x79; 32],
    );
    assert_eq!(
        restored_adapter.get(&tenant, &blob.reference)?,
        Some(blob.clone()),
        "the fresh namespace must contain the exact decryptable ciphertext"
    );

    administrative_storage.delete(final_key)?;
    assert!(adapter.get(&tenant, &blob.reference)?.is_none());
    assert_eq!(
        restored_adapter.get(&tenant, &blob.reference)?,
        Some(blob.clone()),
        "the restored namespace must remain independent of the damaged source"
    );

    let invalid = S3CompatibleObjectStorage::new(
        endpoint,
        "us-east-1",
        bucket,
        format!("{prefix}invalid/"),
        access_key,
        "expired-or-rejected-secret",
        None,
        true,
    )?;
    assert_eq!(
        invalid.get("missing").map_err(|error| error.code()),
        Err(ObjectStorageErrorCode::CredentialsExpired)
    );

    for key in restored_administrative_storage.list_prefix("tenants/", 100)? {
        restored_administrative_storage.delete(&key)?;
    }
    Ok(())
}
