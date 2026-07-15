//! Connects to a compatible HTTPS daemon and performs a typed liveness request.

use cigar_sdk::api::EmptyRequest;
use cigar_sdk::{CallOptions, RemoteClientBuilder, StaticAuthorization};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("CIGAR_ENDPOINT")?;
    let mut builder = RemoteClientBuilder::new(&endpoint)?;
    if std::env::var_os("CIGAR_AUTHORIZATION").is_some()
        || std::env::var_os("CIGAR_TOKEN").is_some()
    {
        return Err(
            "raw authorization environment values are forbidden; use CIGAR_AUTHORIZATION_FILE"
                .into(),
        );
    }
    if let Some(path) = std::env::var_os("CIGAR_AUTHORIZATION_FILE") {
        let authorization = StaticAuthorization::from_file(std::path::PathBuf::from(path))?;
        builder = builder.authorization_provider(Arc::new(authorization));
    }
    let (client, compatibility) = builder.connect().await?;
    let liveness = client
        .get_liveness(EmptyRequest {}, CallOptions::read())
        .await?;
    println!(
        "api={} live={}",
        compatibility.capabilities.api_version, liveness.value.live
    );
    Ok(())
}
