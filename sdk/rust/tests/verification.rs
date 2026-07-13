//! Bundle, manifest, delta digest, and exact application tests.

use cigar_sdk::api::{
    BundleIdRequest, ContextDeltaResponse, GetContextBundleOperation, TypedOperation,
    encode_operation_payload,
};
use cigar_sdk::protocol::{
    ContentDigest, ContextBundle, ContextDelta, ExtensionMap, SchemaVersion, SelectionManifest,
    VersionId,
};
use cigar_sdk::{
    CallOptions, Client, ClientTransport, ErrorKind, SdkError, SdkFuture, TransportCall,
    TransportEventStream, apply_verified_delta, delta_digest, semantic_bundle_id,
    semantic_manifest_id, verify_bundle_manifest, verify_delta,
};
use std::sync::Arc;

fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        character.to_string().repeat(64)
    ))?)
}

fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
    Ok(VersionId::new(digest(character)?.as_str())?)
}

fn manifest() -> Result<SelectionManifest, Box<dyn std::error::Error>> {
    let mut manifest = SelectionManifest {
        schema_version: SchemaVersion::new("cigar.selection-manifest", 1)?,
        manifest_id: version('0')?,
        contract_digest: digest('a')?,
        entries: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    manifest.manifest_id = semantic_manifest_id(&manifest)?;
    Ok(manifest)
}

fn bundle(
    contract_digest: ContentDigest,
    manifest_digest: ContentDigest,
) -> Result<ContextBundle, Box<dyn std::error::Error>> {
    let mut bundle = ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)?,
        bundle_id: version('0')?,
        contract_digest,
        manifest_digest,
        blocks: Vec::new(),
        total_tokens: 0,
        extensions: ExtensionMap::default(),
    };
    bundle.bundle_id = semantic_bundle_id(&bundle)?;
    Ok(bundle)
}

struct TamperedBundleTransport {
    bundle: ContextBundle,
}

impl ClientTransport for TamperedBundleTransport {
    fn unary<'a>(
        &'a self,
        _call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_sdk::api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            let encoded =
                encode_operation_payload(&self.bundle, cigar_sdk::api::MAX_OPERATION_PAYLOAD_BYTES)
                    .map_err(|_failure| SdkError::protocol())?;
            cigar_sdk::api::ResponseEnvelope::new(
                GetContextBundleOperation::OPERATION_ID,
                encoded,
                None,
                None,
            )
            .map_err(|_failure| SdkError::protocol())
        })
    }

    fn subscribe<'a>(
        &'a self,
        _call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async { Err(SdkError::protocol()) })
    }
}

#[test]
fn semantic_bundle_manifest_and_delta_verify_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest()?;
    let base = bundle(
        manifest.contract_digest.clone(),
        ContentDigest::new(manifest.manifest_id.as_str())?,
    )?;
    verify_bundle_manifest(&base, &manifest)?;
    let target = bundle(digest('b')?, digest('c')?)?;
    let delta = ContextDelta {
        schema_version: SchemaVersion::new("cigar.context-delta", 1)?,
        base_bundle_id: base.bundle_id.clone(),
        target_bundle_id: target.bundle_id.clone(),
        added_blocks: Vec::new(),
        removed_block_ids: Vec::new(),
        resulting_tokens: 0,
    };
    let mut response = ContextDeltaResponse {
        delta,
        delta_digest: digest('0')?,
    };
    response.delta_digest = delta_digest(&response)?;
    verify_delta(&response)?;
    assert_eq!(apply_verified_delta(&base, &target, &response)?, target);
    response.delta_digest = digest('f')?;
    let error = verify_delta(&response)
        .err()
        .ok_or("tampered delta verified")?;
    assert_eq!(error.kind(), ErrorKind::Integrity);
    Ok(())
}

#[tokio::test]
async fn typed_bundle_methods_reject_semantic_identity_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tampered = bundle(digest('a')?, digest('b')?)?;
    let addressed = tampered.bundle_id.clone();
    tampered.bundle_id = version('f')?;
    let client = Client::from_transport(Arc::new(TamperedBundleTransport { bundle: tampered }));
    let result = client
        .get_context_bundle(
            BundleIdRequest {
                bundle_id: addressed,
            },
            CallOptions::read(),
        )
        .await;
    let Err(error) = result else {
        return Err("tampered typed bundle unexpectedly returned".into());
    };
    assert_eq!(error.kind(), ErrorKind::Integrity);
    Ok(())
}
