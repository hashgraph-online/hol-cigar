//! Creates a recipient-bound Honey handoff as Agent A from a reviewed JSON request.

use cigar_sdk::api::CreateHandoffRequest;
use cigar_sdk::protocol::IdempotencyKey;
use cigar_sdk::{CallOptions, RemoteClientBuilder, StaticAuthorization};
use std::path::PathBuf;
use std::sync::Arc;

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [request_name, idempotency_value] = arguments.as_slice() else {
        return Err("usage: agent_a_coordinator REQUEST_JSON IDEMPOTENCY_KEY".into());
    };
    let request_path = PathBuf::from(request_name);
    let metadata = std::fs::symlink_metadata(&request_path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_REQUEST_BYTES
    {
        return Err("handoff request must be a non-empty regular file no larger than 1 MiB".into());
    }
    let request_bytes = std::fs::read(&request_path)?;
    if u64::try_from(request_bytes.len())? != metadata.len() {
        return Err("handoff request changed while it was read".into());
    }
    let request = serde_json::from_slice::<CreateHandoffRequest>(&request_bytes)?;

    if std::env::var_os("CIGAR_AUTHORIZATION").is_some()
        || std::env::var_os("CIGAR_TOKEN").is_some()
    {
        return Err(
            "raw authorization environment values are forbidden; use CIGAR_AUTHORIZATION_FILE"
                .into(),
        );
    }
    let endpoint = std::env::var("CIGAR_ENDPOINT")?;
    let mut builder = RemoteClientBuilder::new(&endpoint)?;
    if endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:")
    {
        builder = builder.allow_insecure_loopback(true);
    }
    let authorization_path = std::env::var_os("CIGAR_AUTHORIZATION_FILE")
        .ok_or("CIGAR_AUTHORIZATION_FILE is required for Agent A")?;
    builder = builder.authorization_provider(Arc::new(StaticAuthorization::from_file(
        PathBuf::from(authorization_path),
    )?));
    let (client, _) = builder.connect().await?;
    let created = client
        .create_handoff(
            request,
            CallOptions::mutation(IdempotencyKey::new(idempotency_value.clone())?),
        )
        .await?;

    // Print only disclosure-safe identifiers and attenuation counts, never the task or references.
    println!(
        "handoff_id={} accepted_capabilities={} rejected_capabilities={} references={}",
        created.value.capsule.handoff_id.as_str(),
        created.value.preview.accepted_capabilities.len(),
        created.value.preview.rejected_capabilities.len(),
        created.value.preview.reference_count,
    );
    Ok(())
}
