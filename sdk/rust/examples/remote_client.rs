//! Connects to a compatible HTTPS daemon and performs a typed liveness request.

use cigar_sdk::api::EmptyRequest;
use cigar_sdk::{AuthorizationValue, CallOptions, RemoteClientBuilder, StaticAuthorization};
use std::sync::Arc;
use zeroize::Zeroize as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("CIGAR_ENDPOINT")?;
    let mut builder = RemoteClientBuilder::new(&endpoint)?;
    if let Ok(mut authorization) = std::env::var("CIGAR_AUTHORIZATION") {
        let value = AuthorizationValue::new(authorization.clone())?;
        authorization.zeroize();
        builder = builder.authorization_provider(Arc::new(StaticAuthorization::new(value)));
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
