//! Extension-manifest authentication and fail-closed activation.

use crate::digest::{manifest_digest, manifest_signing_bytes, raw_content_digest};
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use cigar_crypto::verify_ed25519;
use cigar_protocol::{
    ContentDigest, ExtensionComputeBudget, ExtensionHostCapability, ExtensionId, ExtensionKind,
    ExtensionLimits, ExtensionManifestV1, ExtensionRuntimeKind, ExtensionSemanticVersion,
    NetworkEndpoint, SandboxPreopen, Validate,
};
use std::collections::{BTreeMap, BTreeSet};

/// Operator-owned trust, compatibility, schema, authority, and resource policy.
#[derive(Clone, Debug)]
pub struct ActivationPolicy {
    /// Exact trusted Ed25519 keys by publisher selector.
    pub trusted_publishers: BTreeMap<ExtensionId, [u8; 32]>,
    /// Logical ABI version implemented by this host.
    pub protocol_abi: ExtensionSemanticVersion,
    /// CIGAR application version implemented by this host.
    pub cigar_version: ExtensionSemanticVersion,
    /// Exact approved input/output schema digests for each extension role.
    pub schema_bindings: BTreeMap<ExtensionKind, (ContentDigest, ContentDigest)>,
    /// Runtime kinds enabled by the deployment profile.
    pub allowed_runtimes: BTreeSet<ExtensionRuntimeKind>,
    /// Host capabilities an operator allows extensions to request.
    pub allowed_capabilities: BTreeSet<ExtensionHostCapability>,
    /// Exact endpoints approved for brokered network access.
    pub allowed_network_endpoints: BTreeSet<NetworkEndpoint>,
    /// Exact logical preopens approved for brokered filesystem access.
    pub allowed_filesystem_preopens: BTreeSet<SandboxPreopen>,
    /// Hard operator ceilings which a manifest may not exceed.
    pub maximum_limits: ExtensionLimits,
}

/// Fully authenticated extension metadata safe to hand to a runtime.
#[derive(Clone, Debug)]
pub struct ActivatedExtension {
    manifest: ExtensionManifestV1,
    manifest_digest: ContentDigest,
}

impl ActivatedExtension {
    /// Returns the authenticated immutable manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ExtensionManifestV1 {
        &self.manifest
    }

    /// Returns the domain-separated digest of the signature-excluded manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }
}

/// Authenticates and authorizes a package before any extension code can execute.
pub fn activate_extension(
    manifest: ExtensionManifestV1,
    exact_package_bytes: &[u8],
    exact_implementation_bytes: &[u8],
    policy: &ActivationPolicy,
) -> Result<ActivatedExtension, ExtensionHostError> {
    manifest
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
    policy
        .maximum_limits
        .validate()
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;

    verify_publisher(&manifest, policy)?;
    verify_exact_digests(&manifest, exact_package_bytes, exact_implementation_bytes)?;
    verify_compatibility(&manifest, policy)?;
    verify_schemas(&manifest, policy)?;
    verify_authority(&manifest, policy)?;
    verify_limits(&manifest, &policy.maximum_limits)?;
    verify_compute_kind(&manifest)?;

    let digest = manifest_digest(&manifest)?;
    Ok(ActivatedExtension {
        manifest,
        manifest_digest: digest,
    })
}

fn verify_publisher(
    manifest: &ExtensionManifestV1,
    policy: &ActivationPolicy,
) -> Result<(), ExtensionHostError> {
    let trusted = policy
        .trusted_publishers
        .get(&manifest.publisher_key_id)
        .ok_or_else(|| error(ExtensionHostErrorCode::SignatureInvalid))?;
    let asserted: &[u8; 32] = manifest
        .publisher_public_key
        .as_slice()
        .try_into()
        .map_err(|_error| error(ExtensionHostErrorCode::SignatureInvalid))?;
    if trusted != asserted {
        return Err(error(ExtensionHostErrorCode::SignatureInvalid));
    }
    let signature: &[u8; 64] = manifest
        .signature
        .as_slice()
        .try_into()
        .map_err(|_error| error(ExtensionHostErrorCode::SignatureInvalid))?;
    verify_ed25519(trusted, &manifest_signing_bytes(manifest)?, signature)
        .map_err(|_error| error(ExtensionHostErrorCode::SignatureInvalid))
}

fn verify_exact_digests(
    manifest: &ExtensionManifestV1,
    package: &[u8],
    implementation: &[u8],
) -> Result<(), ExtensionHostError> {
    if raw_content_digest(package)? != manifest.package_digest
        || raw_content_digest(implementation)? != manifest.implementation_digest
    {
        return Err(error(ExtensionHostErrorCode::DigestMismatch));
    }
    Ok(())
}

fn verify_compatibility(
    manifest: &ExtensionManifestV1,
    policy: &ActivationPolicy,
) -> Result<(), ExtensionHostError> {
    let abi = policy.protocol_abi;
    let cigar = policy.cigar_version;
    if abi < manifest.protocol_abi.minimum
        || abi > manifest.protocol_abi.maximum
        || cigar < manifest.compatible_cigar_versions.minimum
        || cigar > manifest.compatible_cigar_versions.maximum
    {
        return Err(error(ExtensionHostErrorCode::IncompatibleVersion));
    }
    Ok(())
}

fn verify_schemas(
    manifest: &ExtensionManifestV1,
    policy: &ActivationPolicy,
) -> Result<(), ExtensionHostError> {
    for binding in &manifest.schema_bindings {
        let Some((input, output)) = policy.schema_bindings.get(&binding.kind) else {
            return Err(error(ExtensionHostErrorCode::DigestMismatch));
        };
        if input != &binding.input_schema_digest || output != &binding.output_schema_digest {
            return Err(error(ExtensionHostErrorCode::DigestMismatch));
        }
    }
    Ok(())
}

fn verify_authority(
    manifest: &ExtensionManifestV1,
    policy: &ActivationPolicy,
) -> Result<(), ExtensionHostError> {
    if !policy.allowed_runtimes.contains(&manifest.runtime)
        || manifest
            .required_host_capabilities
            .iter()
            .any(|capability| !policy.allowed_capabilities.contains(capability))
        || manifest
            .network_allowlist
            .iter()
            .any(|endpoint| !policy.allowed_network_endpoints.contains(endpoint))
        || manifest
            .filesystem_preopens
            .iter()
            .any(|preopen| !policy.allowed_filesystem_preopens.contains(preopen))
    {
        return Err(error(ExtensionHostErrorCode::CapabilityDenied));
    }
    Ok(())
}

fn verify_limits(
    requested: &ExtensionManifestV1,
    maximum: &ExtensionLimits,
) -> Result<(), ExtensionHostError> {
    let requested_limits = &requested.limits;
    let compute_within = match (requested_limits.compute, maximum.compute) {
        (
            ExtensionComputeBudget::Fuel { units: requested },
            ExtensionComputeBudget::Fuel { units: allowed },
        ) => requested <= allowed,
        (
            ExtensionComputeBudget::CpuTime {
                duration: requested,
            },
            ExtensionComputeBudget::CpuTime { duration: allowed },
        ) => requested <= allowed,
        _ => false,
    };
    if requested_limits.max_memory_bytes > maximum.max_memory_bytes
        || !compute_within
        || requested_limits.wall_deadline > maximum.wall_deadline
        || requested_limits.max_input_bytes > maximum.max_input_bytes
        || requested_limits.max_output_bytes > maximum.max_output_bytes
        || requested_limits.max_concurrency > maximum.max_concurrency
        || requested_limits.max_recursion_depth > maximum.max_recursion_depth
        || requested_limits.max_host_calls > maximum.max_host_calls
    {
        return Err(error(ExtensionHostErrorCode::ResourceExhausted));
    }
    Ok(())
}

fn verify_compute_kind(manifest: &ExtensionManifestV1) -> Result<(), ExtensionHostError> {
    let valid = matches!(
        (manifest.runtime, manifest.limits.compute),
        (
            ExtensionRuntimeKind::WasiPreview2,
            ExtensionComputeBudget::Fuel { .. }
        ) | (
            ExtensionRuntimeKind::BuiltIn
                | ExtensionRuntimeKind::IsolatedSubprocess
                | ExtensionRuntimeKind::RemoteGrpc,
            ExtensionComputeBudget::CpuTime { .. }
        )
    );
    if valid {
        Ok(())
    } else {
        Err(error(ExtensionHostErrorCode::InvalidInput))
    }
}
