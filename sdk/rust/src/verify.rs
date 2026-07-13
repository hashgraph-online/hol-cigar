//! Local semantic identity, manifest, digest, and delta verification.

use crate::{ErrorKind, SdkError};
use cigar_api::{ContextDeltaResponse, TypedOperation};
use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_protocol::{
    ContentDigest, ContextBlock, ContextBundle, RetryClass, SelectionManifest, Validate, VersionId,
};
use sha2::{Digest as _, Sha256};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

/// Verifies the shared cross-SDK quickstart fixture and returns its semantic bundle identity.
pub fn verify_semantic_bundle_fixture_json(bytes: &[u8]) -> Result<VersionId, SdkError> {
    cigar_canon::parse_strict_json(bytes).map_err(|_failure| integrity_error())?;
    let fixture: SemanticBundleFixture =
        serde_json::from_slice(bytes).map_err(|_failure| integrity_error())?;
    if fixture.schema_version != "cigar.sdk-semantic-bundle-fixture.v1" {
        return Err(integrity_error());
    }
    verify_bundle(&fixture.bundle)?;
    let expected =
        VersionId::new(fixture.expected_bundle_id).map_err(|_failure| integrity_error())?;
    let computed = semantic_bundle_id(&fixture.bundle)?;
    if computed == expected && fixture.bundle.bundle_id == expected {
        Ok(computed)
    } else {
        Err(integrity_error())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticBundleFixture {
    schema_version: String,
    bundle: ContextBundle,
    expected_bundle_id: String,
}

/// Computes the frozen domain-separated semantic identity for a context bundle.
pub fn semantic_bundle_id(bundle: &ContextBundle) -> Result<VersionId, SdkError> {
    bundle.validate().map_err(|_failure| integrity_error())?;
    let identity = semantic_multihash_v1(SemanticEnvelopeProfile::Bundle, bundle)
        .map_err(|_failure| integrity_error())?;
    VersionId::new(identity).map_err(|_failure| integrity_error())
}

/// Verifies structural validity and the bundle's self-derived semantic identity.
pub fn verify_bundle(bundle: &ContextBundle) -> Result<(), SdkError> {
    if semantic_bundle_id(bundle)? == bundle.bundle_id {
        Ok(())
    } else {
        Err(integrity_error())
    }
}

/// Computes the frozen domain-separated semantic identity for a selection manifest.
pub fn semantic_manifest_id(manifest: &SelectionManifest) -> Result<VersionId, SdkError> {
    manifest.validate().map_err(|_failure| integrity_error())?;
    let identity = semantic_multihash_v1(SemanticEnvelopeProfile::Manifest, manifest)
        .map_err(|_failure| integrity_error())?;
    VersionId::new(identity).map_err(|_failure| integrity_error())
}

/// Verifies structural validity and the manifest's self-derived semantic identity.
pub fn verify_manifest(manifest: &SelectionManifest) -> Result<(), SdkError> {
    if semantic_manifest_id(manifest)? == manifest.manifest_id {
        Ok(())
    } else {
        Err(integrity_error())
    }
}

/// Verifies a bundle and its complete manifest are bound to the same contract and digest.
pub fn verify_bundle_manifest(
    bundle: &ContextBundle,
    manifest: &SelectionManifest,
) -> Result<(), SdkError> {
    verify_bundle(bundle)?;
    verify_manifest(manifest)?;
    if bundle.contract_digest == manifest.contract_digest
        && bundle.manifest_digest.as_str() == manifest.manifest_id.as_str()
    {
        Ok(())
    } else {
        Err(integrity_error())
    }
}

/// Computes the exact plain SHA-256 multihash used to seal one delta JSON record.
pub fn delta_digest(response: &ContextDeltaResponse) -> Result<ContentDigest, SdkError> {
    response
        .delta
        .validate()
        .map_err(|_failure| integrity_error())?;
    let bytes = serde_json::to_vec(&response.delta).map_err(|_failure| integrity_error())?;
    sha256_multihash(&bytes)
}

/// Verifies the exact delta-record digest returned by the compile operation.
pub fn verify_delta(response: &ContextDeltaResponse) -> Result<(), SdkError> {
    if delta_digest(response)? == response.delta_digest {
        Ok(())
    } else {
        Err(integrity_error())
    }
}

/// Applies a verified delta and proves the result exactly equals the expected target bundle.
pub fn apply_verified_delta(
    base: &ContextBundle,
    expected_target: &ContextBundle,
    response: &ContextDeltaResponse,
) -> Result<ContextBundle, SdkError> {
    verify_bundle(base)?;
    verify_bundle(expected_target)?;
    verify_delta(response)?;
    let delta = &response.delta;
    if delta.base_bundle_id != base.bundle_id
        || delta.target_bundle_id != expected_target.bundle_id
        || delta.resulting_tokens != expected_target.total_tokens
    {
        return Err(integrity_error());
    }
    let mut blocks: BTreeMap<VersionId, ContextBlock> = base
        .blocks
        .iter()
        .map(|block| (block.block_id.clone(), block.clone()))
        .collect();
    for block_id in &delta.removed_block_ids {
        if blocks.remove(block_id).is_none() {
            return Err(integrity_error());
        }
    }
    for block in &delta.added_blocks {
        if blocks
            .insert(block.block_id.clone(), block.clone())
            .is_some()
        {
            return Err(integrity_error());
        }
    }
    let actual_ids: BTreeSet<_> = blocks.keys().collect();
    let expected_ids: BTreeSet<_> = expected_target
        .blocks
        .iter()
        .map(|block| &block.block_id)
        .collect();
    let exact = actual_ids == expected_ids
        && expected_target
            .blocks
            .iter()
            .all(|block| blocks.get(&block.block_id) == Some(block));
    if exact {
        Ok(expected_target.clone())
    } else {
        Err(integrity_error())
    }
}

pub(crate) fn verify_typed_response<O: TypedOperation>(
    response: &O::Response,
) -> Result<(), SdkError> {
    let response = response as &dyn Any;
    match O::OPERATION_ID {
        "compileContextBundle" | "getContextBundle" => response
            .downcast_ref::<ContextBundle>()
            .ok_or_else(integrity_error)
            .and_then(verify_bundle),
        "getContextBundleManifest" => response
            .downcast_ref::<SelectionManifest>()
            .ok_or_else(integrity_error)
            .and_then(verify_manifest),
        "compileContextDelta" => response
            .downcast_ref::<ContextDeltaResponse>()
            .ok_or_else(integrity_error)
            .and_then(verify_delta),
        _ => Ok(()),
    }
}

fn sha256_multihash(bytes: &[u8]) -> Result<ContentDigest, SdkError> {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_failure| integrity_error())?;
    }
    ContentDigest::new(encoded).map_err(|_failure| integrity_error())
}

const fn integrity_error() -> SdkError {
    SdkError::local(
        ErrorKind::Integrity,
        RetryClass::Never,
        "semantic integrity verification failed",
    )
}
