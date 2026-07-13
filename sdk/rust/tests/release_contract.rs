//! Installed-package version and Context ABI binding tests.

use cigar_sdk::CONTEXT_ABI;
use serde::Deserialize;

const CONTEXT_PROTO: &str = include_str!("../../../schemas/proto/context_abi.proto");
const RELEASE_JSON: &str = include_str!("../release.json");

#[derive(Deserialize)]
struct ReleaseMetadata {
    schema_version: String,
    name: String,
    version: String,
    context_abi: String,
}

#[test]
fn release_metadata_binds_package_version_and_context_abi() -> Result<(), Box<dyn std::error::Error>>
{
    let release: ReleaseMetadata = serde_json::from_str(RELEASE_JSON)?;
    assert_eq!(release.schema_version, "cigar.sdk-release.v1");
    assert_eq!(release.name, "cigar-sdk");
    assert_eq!(release.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(release.context_abi, CONTEXT_ABI);
    assert_eq!(CONTEXT_ABI, "cigar.context.v1");
    assert!(
        CONTEXT_PROTO
            .lines()
            .any(|line| { line.trim() == format!("package {CONTEXT_ABI};") })
    );
    Ok(())
}
