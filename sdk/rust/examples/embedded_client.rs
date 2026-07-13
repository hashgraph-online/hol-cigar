//! Starts the complete production daemon without listeners and shuts it down in order.

#[cfg(feature = "embedded-daemon")]
use cigar_daemon::DaemonConfig;
#[cfg(feature = "embedded-daemon")]
use cigar_sdk::api::EmptyRequest;
#[cfg(feature = "embedded-daemon")]
use cigar_sdk::{
    CallOptions, DaemonEmbeddedRuntimeFactory, EmbeddedClientBuilder, PolicyProfile,
    SqliteDurability, StorageProfile,
};
#[cfg(feature = "embedded-daemon")]
use std::sync::Arc;

#[cfg(feature = "embedded-daemon")]
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[cfg(feature = "embedded-daemon")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: embedded_client CONFIG")?;
    let metadata = std::fs::metadata(&path)?;
    if metadata.len() > MAX_CONFIG_BYTES || !metadata.is_file() {
        return Err("configuration file is invalid or exceeds 1 MiB".into());
    }
    let bytes = std::fs::read(&path)?;
    if u64::try_from(bytes.len())? > MAX_CONFIG_BYTES {
        return Err("configuration file changed beyond the 1 MiB bound".into());
    }
    let config = DaemonConfig::from_toml(std::str::from_utf8(&bytes)?)?;
    let database = config.production.metadata_database.clone();
    let policy = config.production.policy_profile_file.clone();
    let factory = Arc::new(DaemonEmbeddedRuntimeFactory::new(config)?);
    let client = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Sqlite {
            path: database,
            durability: SqliteDurability::Full,
            maximum_connections: 4,
        })
        .policy_profile(PolicyProfile::LocalFile { path: policy })
        .build()
        .await?;
    let version = client
        .get_version(EmptyRequest {}, CallOptions::read())
        .await?;
    println!("cigar {}", version.value.version);
    client.shutdown().await?;
    Ok(())
}

#[cfg(not(feature = "embedded-daemon"))]
fn main() {
    eprintln!("enable the embedded-daemon feature to run this example");
}
