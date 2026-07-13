//! Concrete production daemon adapter preflight tests.
#![cfg(all(feature = "embedded-daemon", unix))]

use cigar_daemon::DaemonConfig;
use cigar_sdk::{
    DaemonEmbeddedRuntimeFactory, EmbeddedClientBuilder, ErrorKind, PolicyProfile,
    SqliteDurability, StorageProfile,
};
use std::sync::Arc;

fn configuration(root: &std::path::Path) -> String {
    let state = root.join("state");
    let runtime = root.join("run");
    format!(
        r#"
mode = "local"
state_directory = "{}"
runtime_directory = "{}"
unix_socket = "{}"
request_deadline_ms = 30000
shutdown_deadline_ms = 30000
max_request_bytes = 1048576
max_expansion_ratio = 16

[workers]
ingestion = 4
indexing = 4
invalidation = 8
compilation = 2
outbox = 8
reconciliation = 4
lease_cleanup = 2
backup = 1
garbage_collection = 2

[production]
project_directory = "{}"
metadata_database = "{}"
blob_directory = "{}"
blob_key_reference_directory = "{}"
keystore_file = "{}"
keystore_passphrase_file = "{}"
cursor_signing_key_file = "{}"
effect_checkpoint_file = "{}"
policy_profile_file = "{}"
authority_file = "{}"
source_registry_file = "{}"
effect_registry_file = "{}"

[resources]
global_request_concurrency = 32
per_tenant_request_concurrency = 8
blocking_active = 2
blocking_queued = 8
idempotency_wait_ms = 30000

[telemetry]
export_timeout_ms = 5000
metric_interval_ms = 30000
"#,
        state.display(),
        runtime.display(),
        runtime.join("cigard.sock").display(),
        root.display(),
        state.join("metadata.sqlite3").display(),
        state.join("blobs").display(),
        state.join("blob-keys").display(),
        state.join("keystore.cigar").display(),
        root.join("secrets/passphrase").display(),
        state.join("cursor.key").display(),
        root.join("effect-checkpoints/checkpoints.json").display(),
        root.join("config/policy.json").display(),
        root.join("config/authority.json").display(),
        root.join("config/sources.json").display(),
        root.join("config/effects.json").display(),
    )
}

#[tokio::test]
async fn concrete_factory_derives_identity_and_binds_exact_profiles()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let config = DaemonConfig::from_toml(&configuration(&root))?;
    let database = config.production.metadata_database.clone();
    let policy = config.production.policy_profile_file.clone();
    let factory = Arc::new(DaemonEmbeddedRuntimeFactory::new(config)?);

    let mismatch = EmbeddedClientBuilder::new(factory.clone())
        .storage_profile(StorageProfile::Memory {
            maximum_records: 1_024,
        })
        .policy_profile(PolicyProfile::LocalFile {
            path: policy.clone(),
        })
        .build()
        .await;
    let Err(error) = mismatch else {
        return Err("mismatched production profiles unexpectedly started".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidConfiguration);

    let missing_trusted_inputs = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Sqlite {
            path: database,
            durability: SqliteDurability::Full,
            maximum_connections: 4,
        })
        .policy_profile(PolicyProfile::LocalFile { path: policy })
        .build()
        .await;
    let Err(error) = missing_trusted_inputs else {
        return Err("missing production trust inputs unexpectedly started".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    Ok(())
}
