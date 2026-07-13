use crate::broker::{
    CapabilityBroker, FinalSecretBoundary, NetworkBoundary, ProtectedDataAuthorization,
    ProtectedDataPolicy,
};
use crate::clock::SystemHostClock;
use crate::digest::{manifest_signing_bytes, raw_content_digest};
use crate::error::{ExtensionHostError, ExtensionHostErrorCode};
use crate::frame::FrameCodec;
use crate::host::{
    ExtensionBackend, ExtensionHost, InvocationCancellation, InvocationRequest, RuntimeResponse,
    extension_response_digest, host_call_transcript_digest,
};
use crate::manifest::{ActivatedExtension, ActivationPolicy, activate_extension};
use crate::subprocess::GuestHostCallRequest;
use crate::subprocess::{IsolatedSubprocessBackend, SubprocessSandbox};
use crate::wasi::WasiPreview2Backend;
use crate::{
    AuthenticatedRemoteBridge, DeterminismVector, DeterministicVectorRunner, RemoteGrpcBackend,
    RemoteIdentity,
};
use cigar_crypto::{SecretBytes, ed25519_public_key, sign_ed25519};
use cigar_protocol::limits::{MAX_EXTENSION_FUEL, MAX_EXTENSION_KINDS};
use cigar_protocol::{
    CigarVersionRange, Classification, DurationNanos, ExtensionAbiVersionRange,
    ExtensionComputeBudget, ExtensionDeterminism, ExtensionHostCapability, ExtensionId,
    ExtensionInvocationV1, ExtensionKind, ExtensionLimits, ExtensionManifestV1, NetworkEndpoint,
    NetworkHost, NetworkTransport, RecordId, SandboxAccess, SandboxPath, SandboxPreopen,
    SchemaVersion, UtcTimestamp, Validate,
};
use cigar_protocol::{
    ExtensionResponseOutcome, ExtensionResponseV1, ExtensionRuntimeKind, ExtensionSchemaBinding,
    ExtensionSemanticVersion,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PACKAGE_BYTES: &[u8] = b"signed-extension-package";
const DEFAULT_IMPLEMENTATION: &[u8] = b"signed-extension-implementation";

// Compile the published WIT on every package test run so documentation and the dynamic scalar
// linker cannot silently drift to an invalid Component Model contract.
#[allow(dead_code, missing_docs)]
mod published_wit_contract {
    wasmtime::component::bindgen!({
        path: "../../spec/context-abi/cigar-extension-world-v1.wit",
        world: "extension",
    });
}

fn version() -> ExtensionSemanticVersion {
    ExtensionSemanticVersion::new(1, 0, 0)
}

fn timestamp_after(duration: Duration) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)? + duration;
    Ok(UtcTimestamp::from_unix_nanos(i128::try_from(
        timestamp.as_nanos(),
    )?)?)
}

fn record(last: char) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{last}"
    ))?)
}

fn limits(
    runtime: ExtensionRuntimeKind,
    concurrency: u16,
) -> Result<ExtensionLimits, Box<dyn std::error::Error>> {
    let compute = if runtime == ExtensionRuntimeKind::WasiPreview2 {
        ExtensionComputeBudget::Fuel { units: 1_000_000 }
    } else {
        ExtensionComputeBudget::CpuTime {
            duration: DurationNanos::new(1_000_000_000)?,
        }
    };
    Ok(ExtensionLimits {
        max_memory_bytes: 64 * 1_024 * 1_024,
        compute,
        wall_deadline: DurationNanos::new(2_000_000_000)?,
        max_input_bytes: 32_768,
        max_output_bytes: 32_768,
        max_concurrency: concurrency,
        max_recursion_depth: 8,
        max_host_calls: 16,
    })
}

struct SignedFixture {
    manifest: ExtensionManifestV1,
    policy: ActivationPolicy,
    secret: SecretBytes,
}

fn signed_fixture(
    runtime: ExtensionRuntimeKind,
    implementation: &[u8],
    entry_point: &str,
    capabilities: Vec<ExtensionHostCapability>,
    endpoint: Option<NetworkEndpoint>,
    preopen: Option<SandboxPreopen>,
    concurrency: u16,
) -> Result<SignedFixture, Box<dyn std::error::Error>> {
    let input_schema = raw_content_digest(b"transform-input-schema-v1")?;
    let output_schema = raw_content_digest(b"transform-output-schema-v1")?;
    let secret = SecretBytes::new(vec![7; 32]);
    let public = ed25519_public_key(&secret)?;
    let mut manifest = ExtensionManifestV1 {
        schema_version: SchemaVersion::new("cigar.extension-manifest", 1)?,
        extension_id: ExtensionId::new("dev.cigar.fixture")?,
        extension_version: version(),
        runtime,
        protocol_abi: ExtensionAbiVersionRange {
            minimum: version(),
            maximum: ExtensionSemanticVersion::new(1, 2, 0),
        },
        implementation_digest: raw_content_digest(implementation)?,
        package_digest: raw_content_digest(PACKAGE_BYTES)?,
        publisher_key_id: ExtensionId::new("dev.cigar.publisher")?,
        publisher_public_key: public.to_vec(),
        signature: vec![0; 64],
        entry_point: SandboxPath::new(entry_point)?,
        kinds: vec![ExtensionKind::Transform],
        schema_bindings: vec![ExtensionSchemaBinding {
            kind: ExtensionKind::Transform,
            input_schema_digest: input_schema.clone(),
            output_schema_digest: output_schema.clone(),
        }],
        source_classifications: vec![Classification::Public, Classification::Internal],
        processors: vec!["processor.fixture".to_owned()],
        determinism: ExtensionDeterminism::Deterministic,
        required_host_capabilities: capabilities.clone(),
        network_allowlist: endpoint.clone().into_iter().collect(),
        filesystem_preopens: preopen.clone().into_iter().collect(),
        limits: limits(runtime, concurrency)?,
        compatible_cigar_versions: CigarVersionRange {
            minimum: version(),
            maximum: ExtensionSemanticVersion::new(1, 9, 0),
        },
    };
    resign(&mut manifest, &secret)?;
    manifest.validate()?;
    let mut trusted_publishers = BTreeMap::new();
    trusted_publishers.insert(manifest.publisher_key_id.clone(), public);
    let mut schemas = BTreeMap::new();
    schemas.insert(ExtensionKind::Transform, (input_schema, output_schema));
    Ok(SignedFixture {
        policy: ActivationPolicy {
            trusted_publishers,
            protocol_abi: version(),
            cigar_version: version(),
            schema_bindings: schemas,
            allowed_runtimes: BTreeSet::from([runtime]),
            allowed_capabilities: capabilities.into_iter().collect(),
            allowed_network_endpoints: endpoint.into_iter().collect(),
            allowed_filesystem_preopens: preopen.into_iter().collect(),
            maximum_limits: limits(runtime, concurrency)?,
        },
        manifest,
        secret,
    })
}

fn resign(
    manifest: &mut ExtensionManifestV1,
    secret: &SecretBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    manifest.signature = vec![0; 64];
    manifest.signature = sign_ed25519(secret, &manifest_signing_bytes(manifest)?)?.to_vec();
    Ok(())
}

fn activate(fixture: &SignedFixture) -> Result<ActivatedExtension, ExtensionHostError> {
    activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        DEFAULT_IMPLEMENTATION,
        &fixture.policy,
    )
}

fn invocation(
    activated: &ActivatedExtension,
    id: char,
    deadline_after: Duration,
) -> Result<ExtensionInvocationV1, Box<dyn std::error::Error>> {
    let manifest = activated.manifest();
    let input = b"protected invocation input".to_vec();
    let has_clock = manifest
        .required_host_capabilities
        .contains(&ExtensionHostCapability::DeterministicClock);
    let has_random = manifest
        .required_host_capabilities
        .contains(&ExtensionHostCapability::DeterministicRandom);
    let binding = manifest
        .schema_bindings
        .first()
        .ok_or("fixture manifest has no schema binding")?;
    Ok(ExtensionInvocationV1 {
        schema_version: SchemaVersion::new("cigar.extension-invocation", 1)?,
        invocation_id: record(id)?,
        extension_id: manifest.extension_id.clone(),
        extension_version: manifest.extension_version,
        manifest_digest: activated.manifest_digest().clone(),
        kind: ExtensionKind::Transform,
        operation: "transform.fixture".to_owned(),
        input_schema_digest: binding.input_schema_digest.clone(),
        input_digest: raw_content_digest(&input)?,
        input,
        authorized_capabilities: manifest.required_host_capabilities.clone(),
        handles: Vec::new(),
        deterministic_clock: if has_clock {
            Some(timestamp_after(Duration::ZERO)?)
        } else {
            None
        },
        deterministic_random_seed: if has_random { vec![9; 32] } else { Vec::new() },
        effective_limits: manifest.limits.clone(),
        issued_at: timestamp_after(Duration::ZERO)?,
        deadline_at: timestamp_after(deadline_after)?,
    })
}

fn successful_response(
    activated: &ActivatedExtension,
    invocation: &ExtensionInvocationV1,
) -> Result<ExtensionResponseV1, Box<dyn std::error::Error>> {
    let output = b"extension output".to_vec();
    let binding = activated
        .manifest()
        .schema_bindings
        .first()
        .ok_or("fixture manifest has no schema binding")?;
    Ok(ExtensionResponseV1 {
        schema_version: SchemaVersion::new("cigar.extension-response", 1)?,
        invocation_id: invocation.invocation_id.clone(),
        outcome: ExtensionResponseOutcome::Succeeded,
        output_schema_digest: Some(binding.output_schema_digest.clone()),
        output_digest: Some(raw_content_digest(&output)?),
        output,
        host_call_count: 0,
        completed_at: timestamp_after(Duration::ZERO)?,
    })
}

#[test]
fn activation_authenticates_every_manifest_binding() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    assert_eq!(
        activated.manifest().extension_id,
        fixture.manifest.extension_id
    );

    let mut bad_signature = fixture.manifest.clone();
    let Some(first_signature_byte) = bad_signature.signature.first_mut() else {
        return Err("fixture signature is empty".into());
    };
    *first_signature_byte ^= 1;
    assert_eq!(
        activate_extension(
            bad_signature,
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &fixture.policy,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::SignatureInvalid)
    );
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            b"substituted package",
            DEFAULT_IMPLEMENTATION,
            &fixture.policy,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DigestMismatch)
    );
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            b"substituted implementation",
            &fixture.policy,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DigestMismatch)
    );

    let mut incompatible = fixture.policy.clone();
    incompatible.protocol_abi = ExtensionSemanticVersion::new(2, 0, 0);
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &incompatible,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::IncompatibleVersion)
    );
    let mut wrong_schema = fixture.policy.clone();
    wrong_schema.schema_bindings.insert(
        ExtensionKind::Transform,
        (raw_content_digest(b"wrong")?, raw_content_digest(b"wrong")?),
    );
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &wrong_schema,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DigestMismatch)
    );

    // A signed manifest cannot use an oversized/duplicated schema-binding set as an
    // allocation or schema-confusion bomb. Structural validation runs before trust checks.
    let mut schema_bomb = fixture.manifest.clone();
    let binding = schema_bomb
        .schema_bindings
        .first()
        .cloned()
        .ok_or("fixture manifest has no schema binding")?;
    schema_bomb.schema_bindings = vec![binding; MAX_EXTENSION_KINDS + 1];
    resign(&mut schema_bomb, &fixture.secret)?;
    assert_eq!(
        activate_extension(
            schema_bomb,
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &fixture.policy,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn activation_rejects_capability_and_resource_escalation() -> Result<(), Box<dyn std::error::Error>>
{
    let endpoint = NetworkEndpoint::new(
        NetworkTransport::Https,
        NetworkHost::new("api.example.test")?,
        443,
    )?;
    let preopen = SandboxPreopen {
        path: SandboxPath::new("workspace")?,
        access: SandboxAccess::ReadOnly,
    };
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        vec![
            ExtensionHostCapability::Network,
            ExtensionHostCapability::FilesystemRead,
        ],
        Some(endpoint),
        Some(preopen),
        2,
    )?;
    let mut no_authority = fixture.policy.clone();
    no_authority.allowed_capabilities.clear();
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &no_authority,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    let mut forbidden_preopen = fixture.policy.clone();
    forbidden_preopen.allowed_filesystem_preopens.clear();
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &forbidden_preopen,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    let mut lower_limits = fixture.policy.clone();
    lower_limits.maximum_limits.max_output_bytes -= 1;
    assert_eq!(
        activate_extension(
            fixture.manifest.clone(),
            PACKAGE_BYTES,
            DEFAULT_IMPLEMENTATION,
            &lower_limits,
        )
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn canonical_frames_reject_oversize_noncanonical_duplicates_and_trailing_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let invocation = invocation(&activated, '1', Duration::from_secs(1))?;
    let codec = FrameCodec::new(65_536)?;
    let frame = codec.encode(&invocation)?;
    assert_eq!(codec.decode::<ExtensionInvocationV1>(&frame)?, invocation);

    let mut trailing = frame.clone();
    trailing.push(0);
    assert_eq!(
        codec
            .decode::<ExtensionInvocationV1>(&trailing)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidFrame)
    );
    let oversized = [0, 1, 0, 1];
    assert!(codec.decode::<ExtensionInvocationV1>(&oversized).is_err());
    let noncanonical = [0, 0, 0, 2, 0x18, 0x00];
    assert!(
        codec
            .decode::<ExtensionInvocationV1>(&noncanonical)
            .is_err()
    );
    let duplicate = [0, 0, 0, 7, 0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
    assert!(codec.decode::<ExtensionInvocationV1>(&duplicate).is_err());
    Ok(())
}

struct AllowProtected;

impl ProtectedDataPolicy for AllowProtected {
    fn authorize(&self, request: ProtectedDataAuthorization<'_>) -> bool {
        request.processor == "processor.fixture"
            && request.classification <= Classification::Internal
    }
}

struct DenyProtected;

impl ProtectedDataPolicy for DenyProtected {
    fn authorize(&self, _request: ProtectedDataAuthorization<'_>) -> bool {
        false
    }
}

struct EchoNetwork;

impl NetworkBoundary for EchoNetwork {
    fn request(
        &self,
        _endpoint: &NetworkEndpoint,
        protected_request: &[u8],
        _maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        Ok(protected_request.to_vec())
    }
}

struct EchoSecret;

impl FinalSecretBoundary for EchoSecret {
    fn dispatch(
        &self,
        secret_reference: &str,
        protected_request: &[u8],
        _maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        if secret_reference != "vault://fixture/key" {
            return Err(ExtensionHostError::new(
                ExtensionHostErrorCode::CapabilityDenied,
            ));
        }
        Ok(protected_request.to_vec())
    }
}

fn broker(
    activated: ActivatedExtension,
    id: char,
    policy: Arc<dyn ProtectedDataPolicy>,
) -> Result<CapabilityBroker, Box<dyn std::error::Error>> {
    let capabilities = activated.manifest().required_host_capabilities.clone();
    let has_clock = capabilities.contains(&ExtensionHostCapability::DeterministicClock);
    let has_random = capabilities.contains(&ExtensionHostCapability::DeterministicRandom);
    Ok(CapabilityBroker::new(
        activated,
        record(id)?,
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        capabilities,
        if has_clock {
            Some(timestamp_after(Duration::ZERO)?)
        } else {
            None
        },
        if has_random { vec![5; 32] } else { Vec::new() },
        policy,
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?)
}

#[test]
fn broker_handles_are_invocation_scoped_and_protected_data_is_policy_gated()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = vec![
        ExtensionHostCapability::SourceRead,
        ExtensionHostCapability::DeterministicClock,
        ExtensionHostCapability::DeterministicRandom,
        ExtensionHostCapability::SecretHandle,
    ];
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        capabilities,
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let first = broker(activated.clone(), '1', Arc::new(AllowProtected))?;
    let second = broker(activated.clone(), '2', Arc::new(AllowProtected))?;
    let handle = first.grant_source(b"protected-canary".to_vec(), Classification::Internal)?;
    assert_eq!(first.read_source(&handle)?, b"protected-canary");
    assert_eq!(
        second
            .read_source(&handle)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidHandle)
    );
    let denied = broker(activated, '3', Arc::new(DenyProtected))?;
    assert_eq!(
        denied
            .grant_source(Vec::new(), Classification::Internal)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    let random_first = first.deterministic_random(48)?;
    let third = broker(activate(&fixture)?, '4', Arc::new(AllowProtected))?;
    assert_eq!(random_first, third.deterministic_random(48)?);
    let secret = first.grant_secret_reference("vault://fixture/key")?;
    assert!(!format!("{first:?}").contains("vault://fixture/key"));
    assert_eq!(
        first.dispatch_with_secret(&secret, b"outbound")?,
        b"outbound"
    );
    first.cancel();
    assert_eq!(
        first
            .deterministic_clock()
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::Cancelled)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn broker_rejects_path_traversal_symlink_escape_and_network_escape()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let endpoint = NetworkEndpoint::new(
        NetworkTransport::Https,
        NetworkHost::new("api.example.test")?,
        443,
    )?;
    let preopen = SandboxPreopen {
        path: SandboxPath::new("workspace")?,
        access: SandboxAccess::ReadOnly,
    };
    let capabilities = vec![
        ExtensionHostCapability::Network,
        ExtensionHostCapability::FilesystemRead,
    ];
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        capabilities,
        Some(endpoint.clone()),
        Some(preopen.clone()),
        2,
    )?;
    let broker = broker(activate(&fixture)?, '1', Arc::new(AllowProtected))?;
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(root.path().join("inside.txt"), b"inside")?;
    fs::write(outside.path().join("secret.txt"), b"outside")?;
    symlink(
        outside.path().join("secret.txt"),
        root.path().join("escape.txt"),
    )?;
    let preopen_handle = broker.grant_preopen(preopen, root.path())?;
    assert_eq!(
        broker.file_read(&preopen_handle, &SandboxPath::new("inside.txt")?)?,
        b"inside"
    );
    assert_eq!(
        broker
            .file_read(&preopen_handle, &SandboxPath::new("escape.txt")?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    assert!(SandboxPath::new("../secret.txt").is_err());
    let endpoint_handle = broker.grant_endpoint(endpoint)?;
    assert_eq!(
        broker.network_request(&endpoint_handle, b"request")?,
        b"request"
    );
    let unlisted = NetworkEndpoint::new(
        NetworkTransport::Https,
        NetworkHost::new("escape.example.test")?,
        443,
    )?;
    assert_eq!(
        broker
            .grant_endpoint(unlisted)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    Ok(())
}

#[test]
fn broker_dispatches_every_host_call_with_a_contiguous_transcript()
-> Result<(), Box<dyn std::error::Error>> {
    let endpoint = NetworkEndpoint::new(
        NetworkTransport::Https,
        NetworkHost::new("api.example.test")?,
        443,
    )?;
    let preopen = SandboxPreopen {
        path: SandboxPath::new("workspace")?,
        access: SandboxAccess::ReadWrite,
    };
    let capabilities = vec![
        ExtensionHostCapability::SourceRead,
        ExtensionHostCapability::BlobRead,
        ExtensionHostCapability::BoundedIterator,
        ExtensionHostCapability::DeterministicClock,
        ExtensionHostCapability::DeterministicRandom,
        ExtensionHostCapability::StructuredTracing,
        ExtensionHostCapability::Cancellation,
        ExtensionHostCapability::Network,
        ExtensionHostCapability::FilesystemRead,
        ExtensionHostCapability::FilesystemWrite,
        ExtensionHostCapability::SecretHandle,
    ];
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        capabilities,
        Some(endpoint.clone()),
        Some(preopen.clone()),
        2,
    )?;
    let broker = broker(activate(&fixture)?, '1', Arc::new(AllowProtected))?;
    let source = broker.grant_source(b"source".to_vec(), Classification::Internal)?;
    let blob = broker.grant_blob(b"blob".to_vec(), Classification::Internal)?;
    let iterator = broker.grant_iterator(vec![b"first".to_vec()])?;
    let endpoint = broker.grant_endpoint(endpoint)?;
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("file.txt"), b"before")?;
    let preopen = broker.grant_preopen(preopen, root.path())?;
    let secret = broker.grant_secret_reference("vault://fixture/key")?;

    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::ReadSource,
            Some(&source),
            &[],
        )?,
        b"source"
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::ReadBlob,
            Some(&blob),
            &[],
        )?,
        b"blob"
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::IteratorNext,
            Some(&iterator),
            &[],
        )?,
        [vec![1], b"first".to_vec()].concat()
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::IteratorNext,
            Some(&iterator),
            &[],
        )?,
        vec![0]
    );
    assert!(
        !broker
            .dispatch_host_call(cigar_protocol::ExtensionHostCallKind::ClockNow, None, &[])?
            .is_empty()
    );
    assert_eq!(
        broker
            .dispatch_host_call(
                cigar_protocol::ExtensionHostCallKind::RandomFill,
                None,
                &8_u32.to_be_bytes(),
            )?
            .len(),
        8
    );
    assert!(
        broker
            .dispatch_host_call(
                cigar_protocol::ExtensionHostCallKind::Trace,
                None,
                b"structured-trace",
            )?
            .is_empty()
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::CheckCancelled,
            None,
            &[],
        )?,
        vec![0]
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::NetworkRequest,
            Some(&endpoint),
            b"network",
        )?,
        b"network"
    );
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::FileRead,
            Some(&preopen),
            b"file.txt",
        )?,
        b"before"
    );
    let mut write_request = Vec::from(u16::try_from("file.txt".len())?.to_be_bytes());
    write_request.extend_from_slice(b"file.txt");
    write_request.extend_from_slice(b"after");
    assert!(
        broker
            .dispatch_host_call(
                cigar_protocol::ExtensionHostCallKind::FileWrite,
                Some(&preopen),
                &write_request,
            )?
            .is_empty()
    );
    assert_eq!(fs::read(root.path().join("file.txt"))?, b"after");
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::ResolveSecret,
            Some(&secret),
            b"secret-boundary",
        )?,
        b"secret-boundary"
    );
    broker.cancel();
    assert_eq!(
        broker.dispatch_host_call(
            cigar_protocol::ExtensionHostCallKind::CheckCancelled,
            None,
            &[],
        )?,
        vec![1]
    );
    let transcript = broker.transcript()?;
    assert_eq!(transcript.len(), 13);
    assert!(
        transcript
            .iter()
            .enumerate()
            .all(|(index, call)| { usize::try_from(call.ordinal).ok() == index.checked_add(1) })
    );
    Ok(())
}

#[test]
fn broker_transcript_budget_is_atomic_across_concurrent_host_calls()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        vec![ExtensionHostCapability::StructuredTracing],
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let budget = CapabilityBroker::new_transcript_budget_for_test(30_000);
    let mut first_broker = broker(activated.clone(), '1', Arc::new(AllowProtected))?;
    let mut second_broker = broker(activated, '2', Arc::new(AllowProtected))?;
    assert_eq!(
        first_broker.maximum_transcript_bytes_for_test(),
        cigar_canon::MAX_CANONICAL_INPUT_BYTES
    );
    first_broker.set_transcript_budget_for_test(&budget)?;
    second_broker.set_transcript_budget_for_test(&budget)?;
    first_broker.set_maximum_transcript_bytes_for_test(30_000);
    second_broker.set_maximum_transcript_bytes_for_test(30_000);
    let first_broker = Arc::new(first_broker);
    let second_broker = Arc::new(second_broker);
    let barrier = Arc::new(Barrier::new(9));
    let workers = (0..8)
        .map(|index| {
            let broker = if index % 2 == 0 {
                first_broker.clone()
            } else {
                second_broker.clone()
            };
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                broker.dispatch_host_call(
                    cigar_protocol::ExtensionHostCallKind::Trace,
                    None,
                    &vec![7_u8; 4_096],
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().map_err(|_| "broker worker panicked"))
        .collect::<Result<Vec<_>, _>>()?;
    let successes = results.iter().filter(|result| result.is_ok()).count();
    assert!(successes > 0 && successes < results.len());
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|failure| failure.code() == ExtensionHostErrorCode::ResourceExhausted)
    );
    let first_transcript = first_broker.transcript()?;
    let second_transcript = second_broker.transcript()?;
    assert_eq!(first_transcript.len() + second_transcript.len(), successes);
    assert!(
        first_transcript
            .iter()
            .enumerate()
            .all(|(index, call)| usize::try_from(call.ordinal).ok() == index.checked_add(1))
    );
    assert!(
        second_transcript
            .iter()
            .enumerate()
            .all(|(index, call)| usize::try_from(call.ordinal).ok() == index.checked_add(1))
    );
    assert!(budget.reserved_bytes() <= 30_000);
    drop(first_transcript);
    drop(second_transcript);
    drop(first_broker);
    drop(second_broker);
    assert_eq!(budget.reserved_bytes(), 0);
    Ok(())
}

enum BackendBehavior {
    Success,
    BrokerTrace,
    CrashFirst,
    CrashAfterResponse,
    InvalidOutput,
    WaitForRelease {
        entered: Arc<Barrier>,
        release: Arc<AtomicBool>,
    },
    WaitForCancel {
        entered: Arc<Barrier>,
    },
}

struct TestBackend {
    activated: ActivatedExtension,
    calls: AtomicU32,
    behavior: BackendBehavior,
}

impl ExtensionBackend for TestBackend {
    fn runtime_kind(&self) -> ExtensionRuntimeKind {
        ExtensionRuntimeKind::BuiltIn
    }

    fn invoke(
        &self,
        invocation: &ExtensionInvocationV1,
        deadline: Instant,
        cancellation: InvocationCancellation,
        broker: Option<Arc<CapabilityBroker>>,
    ) -> Result<RuntimeResponse, ExtensionHostError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        match &self.behavior {
            BackendBehavior::Success => Ok(RuntimeResponse::completed(
                successful_response(&self.activated, invocation).map_err(|_error| {
                    ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                })?,
            )),
            BackendBehavior::BrokerTrace => {
                let broker = broker.ok_or_else(|| {
                    ExtensionHostError::new(ExtensionHostErrorCode::BackendUnavailable)
                })?;
                broker.dispatch_host_call(
                    cigar_protocol::ExtensionHostCallKind::Trace,
                    None,
                    b"protected-observation-trace-canary",
                )?;
                let mut response =
                    successful_response(&self.activated, invocation).map_err(|_error| {
                        ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                    })?;
                response.host_call_count = broker.host_call_count();
                Ok(RuntimeResponse::completed(response))
            }
            BackendBehavior::CrashFirst if call == 1 => Err(ExtensionHostError::new(
                ExtensionHostErrorCode::ExtensionCrashed,
            )),
            BackendBehavior::CrashFirst => Ok(RuntimeResponse::completed(
                successful_response(&self.activated, invocation).map_err(|_error| {
                    ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                })?,
            )),
            BackendBehavior::CrashAfterResponse => Ok(RuntimeResponse::crashed_after_response(
                successful_response(&self.activated, invocation).map_err(|_error| {
                    ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                })?,
            )),
            BackendBehavior::InvalidOutput => {
                let mut response =
                    successful_response(&self.activated, invocation).map_err(|_error| {
                        ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                    })?;
                response.output.extend_from_slice(b"tampered");
                Ok(RuntimeResponse::completed(response))
            }
            BackendBehavior::WaitForRelease { entered, release } => {
                entered.wait();
                while !release.load(Ordering::SeqCst) {
                    if Instant::now() >= deadline {
                        return Err(ExtensionHostError::new(
                            ExtensionHostErrorCode::DeadlineExceeded,
                        ));
                    }
                    thread::yield_now();
                }
                Ok(RuntimeResponse::completed(
                    successful_response(&self.activated, invocation).map_err(|_error| {
                        ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                    })?,
                ))
            }
            BackendBehavior::WaitForCancel { entered } => {
                entered.wait();
                while !cancellation.is_cancelled() && Instant::now() < deadline {
                    thread::yield_now();
                }
                Ok(RuntimeResponse::completed(
                    successful_response(&self.activated, invocation).map_err(|_error| {
                        ExtensionHostError::new(ExtensionHostErrorCode::InvalidResponse)
                    })?,
                ))
            }
        }
    }
}

fn host_with_backend(
    activated: ActivatedExtension,
    behavior: BackendBehavior,
) -> Result<(Arc<ExtensionHost>, Arc<TestBackend>), ExtensionHostError> {
    let backend = Arc::new(TestBackend {
        activated: activated.clone(),
        calls: AtomicU32::new(0),
        behavior,
    });
    let host = Arc::new(ExtensionHost::new(Arc::new(SystemHostClock)));
    host.register(activated, backend.clone())?;
    Ok((host, backend))
}

#[test]
fn host_never_retries_and_rejects_crash_after_response_and_output_flood()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let (host, backend) = host_with_backend(activated.clone(), BackendBehavior::CrashFirst)?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '1',
            Duration::from_secs(1),
        )?)?)
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ExtensionCrashed)
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    let retry_invocation = invocation(&activated, '2', Duration::from_secs(1))?;
    let broker = Arc::new(broker(activated.clone(), '2', Arc::new(AllowProtected))?);
    let first = InvocationRequest::new(retry_invocation.clone())?.with_broker(broker.clone())?;
    assert_eq!(
        InvocationRequest::new(retry_invocation)
            .and_then(|request| request.with_broker(broker))
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidInput)
    );
    let (host, backend) = host_with_backend(activated.clone(), BackendBehavior::CrashFirst)?;
    assert_eq!(
        host.invoke(first).err().map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ExtensionCrashed)
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    let (host, _) = host_with_backend(activated.clone(), BackendBehavior::CrashAfterResponse)?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '3',
            Duration::from_secs(1)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ExtensionCrashed)
    );
    let (host, _) = host_with_backend(activated.clone(), BackendBehavior::InvalidOutput)?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '4',
            Duration::from_secs(1)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DigestMismatch)
    );
    Ok(())
}

#[test]
fn observed_invocation_binds_exact_deterministic_replay_records()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        vec![ExtensionHostCapability::StructuredTracing],
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let invocation = invocation(&activated, '5', Duration::from_secs(1))?;
    let broker = Arc::new(broker(activated.clone(), '5', Arc::new(AllowProtected))?);
    let (host, _) = host_with_backend(activated.clone(), BackendBehavior::BrokerTrace)?;
    let outcome =
        host.invoke_observed(InvocationRequest::new(invocation.clone())?.with_broker(broker)?)?;

    outcome.validate()?;
    assert!(!outcome.replay_dependency_required());
    assert_eq!(outcome.invocation(), &invocation);
    assert_eq!(
        outcome.observation().invocation_id,
        invocation.invocation_id
    );
    assert_eq!(
        outcome.observation().manifest_digest,
        *activated.manifest_digest()
    );
    assert_eq!(
        outcome.observation().implementation_digest,
        activated.manifest().implementation_digest
    );
    assert_eq!(
        outcome.observation().package_digest,
        activated.manifest().package_digest
    );
    assert_eq!(
        outcome.observation().effective_limits,
        invocation.effective_limits
    );
    assert_eq!(outcome.host_call_transcript().len(), 1);
    assert_eq!(
        outcome.observation().host_call_transcript_digest,
        host_call_transcript_digest(outcome.host_call_transcript())?
    );
    assert_eq!(
        outcome.response_digest(),
        &extension_response_digest(outcome.response())?
    );
    let cloned_outcome = outcome.clone();
    assert!(std::ptr::eq(
        outcome.host_call_transcript().as_ptr(),
        cloned_outcome.host_call_transcript().as_ptr()
    ));
    drop(cloned_outcome);
    let rendered = format!("{outcome:?}");
    assert!(!rendered.contains("protected invocation input"));
    assert!(!rendered.contains("extension output"));
    assert!(!rendered.contains("protected-observation-trace-canary"));

    let (_, response, observation, transcript, response_digest) = outcome.into_parts();
    assert_eq!(observation.outcome, response.outcome);
    assert_eq!(observation.output_digest, response.output_digest);
    assert_eq!(response_digest, extension_response_digest(&response)?);
    assert_eq!(
        observation.host_call_transcript_digest,
        host_call_transcript_digest(&transcript)?
    );
    Ok(())
}

#[test]
fn nondeterministic_observation_is_mandatory_and_failures_never_commit_an_outcome()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        vec![ExtensionHostCapability::StructuredTracing],
        None,
        None,
        2,
    )?;
    fixture.manifest.determinism = ExtensionDeterminism::Nondeterministic;
    resign(&mut fixture.manifest, &fixture.secret)?;
    let activated = activate(&fixture)?;
    let invocation = invocation(&activated, '6', Duration::from_secs(1))?;
    let (host, backend) = host_with_backend(activated.clone(), BackendBehavior::BrokerTrace)?;

    assert_eq!(
        host.invoke(InvocationRequest::new(invocation.clone(),)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidInput)
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    let broker = Arc::new(broker(activated.clone(), '6', Arc::new(AllowProtected))?);
    let outcome =
        host.invoke_observed(InvocationRequest::new(invocation.clone())?.with_broker(broker)?)?;
    assert!(outcome.replay_dependency_required());
    assert_eq!(
        outcome.observation().determinism,
        ExtensionDeterminism::Nondeterministic
    );
    assert_eq!(outcome.observation().input_digest, invocation.input_digest);
    assert_eq!(
        outcome.observation().output_digest,
        outcome.response().output_digest
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    let mut changed_transcript = outcome.host_call_transcript().to_vec();
    let first_call = changed_transcript.first_mut().ok_or("missing transcript")?;
    first_call.request.push(0);
    first_call.request_digest = raw_content_digest(&first_call.request)?;
    assert_ne!(
        host_call_transcript_digest(&changed_transcript)?,
        outcome.observation().host_call_transcript_digest
    );

    for behavior in [
        BackendBehavior::CrashAfterResponse,
        BackendBehavior::InvalidOutput,
    ] {
        let (failing_host, _) = host_with_backend(activated.clone(), behavior)?;
        let result = failing_host.invoke_observed(InvocationRequest::new(invocation.clone())?);
        let Err(failure) = result else {
            return Err("untrusted backend result produced a commit outcome".into());
        };
        let rendered = format!("{failure:?}");
        assert!(!rendered.contains("protected invocation input"));
        assert!(!rendered.contains("extension output"));
        assert!(!rendered.contains("tampered"));
    }
    Ok(())
}

#[test]
fn host_enforces_concurrency_and_cancel_races() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate(&fixture)?;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(AtomicBool::new(false));
    let (host, _) = host_with_backend(
        activated.clone(),
        BackendBehavior::WaitForRelease {
            entered: entered.clone(),
            release: release.clone(),
        },
    )?;
    let threaded_host = host.clone();
    let first = InvocationRequest::new(invocation(&activated, '1', Duration::from_secs(1))?)?;
    let worker = thread::spawn(move || threaded_host.invoke(first));
    entered.wait();
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '2',
            Duration::from_secs(1)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );
    release.store(true, Ordering::SeqCst);
    worker
        .join()
        .map_err(|_panic| "concurrency worker panicked")??;

    let entered = Arc::new(Barrier::new(2));
    let (host, _) = host_with_backend(
        activated.clone(),
        BackendBehavior::WaitForCancel {
            entered: entered.clone(),
        },
    )?;
    let request = InvocationRequest::new(invocation(&activated, '3', Duration::from_secs(1))?)?;
    let cancellation = request.cancellation();
    let worker_host = host.clone();
    let worker = thread::spawn(move || worker_host.invoke(request));
    entered.wait();
    cancellation.cancel();
    assert_eq!(
        worker
            .join()
            .map_err(|_panic| "cancellation worker panicked")?
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::Cancelled)
    );
    Ok(())
}

#[cfg(unix)]
fn executable_script(
    directory: &Path,
    body: &str,
) -> Result<(std::path::PathBuf, Vec<u8>), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("fixture.sh");
    let bytes = format!("#!/bin/sh\n{body}\n").into_bytes();
    fs::write(&path, &bytes)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok((path, bytes))
}

#[cfg(unix)]
fn executable_python_script(
    directory: &Path,
    body: &str,
) -> Result<(std::path::PathBuf, Vec<u8>), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("fixture.py");
    let bytes = format!("#!/usr/bin/python3\n{body}\n").into_bytes();
    fs::write(&path, &bytes)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions)?;
    Ok((path, bytes))
}

#[cfg(unix)]
fn shell_octal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:03o}")).collect()
}

#[cfg(unix)]
fn python_blob_call_script(
    invocation_id: &RecordId,
    response_frame: &[u8],
    forge_handle: bool,
) -> String {
    format!(
        r#"import sys, struct
def head(major, value):
    if value < 24: return bytes([(major << 5) | value])
    if value <= 255: return bytes([(major << 5) | 24, value])
    if value <= 65535: return bytes([(major << 5) | 25]) + value.to_bytes(2, 'big')
    if value <= 4294967295: return bytes([(major << 5) | 26]) + value.to_bytes(4, 'big')
    return bytes([(major << 5) | 27]) + value.to_bytes(8, 'big')
def enc(value):
    if isinstance(value, int): return head(0, value)
    if isinstance(value, str):
        data = value.encode('utf-8'); return head(3, len(data)) + data
    if isinstance(value, list): return head(4, len(value)) + b''.join(enc(item) for item in value)
    if isinstance(value, dict):
        entries = sorted(((enc(key), enc(item)) for key, item in value.items()), key=lambda item: item[0])
        return head(5, len(entries)) + b''.join(key + item for key, item in entries)
    raise RuntimeError('unsupported')
prefix = sys.stdin.buffer.read(4)
size = int.from_bytes(prefix, 'big')
payload = sys.stdin.buffer.read(size)
marker = b'\x67handles\x81\x78\x2b'
position = payload.find(marker)
if position < 0: sys.exit(71)
start = position + len(marker)
handle = payload[start:start + 43].decode('ascii')
if {forge_handle}: handle = ('A' if handle[0] != 'A' else 'B') + handle[1:]
call = enc({{'invocation_id': '{invocation_id}', 'ordinal': 1, 'kind': 'read_blob', 'handle': handle, 'request': []}})
sys.stdout.buffer.write(len(call).to_bytes(4, 'big') + call)
sys.stdout.buffer.flush()
reply_size = int.from_bytes(sys.stdin.buffer.read(4), 'big')
sys.stdin.buffer.read(reply_size)
sys.stdout.buffer.write(bytes.fromhex('{response_hex}'))
sys.stdout.buffer.flush()
"#,
        forge_handle = if forge_handle { "True" } else { "False" },
        invocation_id = invocation_id.as_str(),
        response_hex = response_frame
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

fn component_output_wat(response_frame: &[u8], host_call: Option<(u32, u32)>) -> String {
    let host_calls = host_call.into_iter().collect::<Vec<_>>();
    component_output_wat_with_calls(response_frame, &host_calls)
}

fn component_output_wat_with_calls(response_frame: &[u8], host_calls: &[(u32, u32)]) -> String {
    let output_instructions = response_frame
        .iter()
        .enumerate()
        .map(|(index, byte)| format!("i32.const {index} i32.const {byte} call $output-byte drop"))
        .collect::<Vec<_>>()
        .join(" ");
    let component_host_import = if host_calls.is_empty() {
        ""
    } else {
        "(import \"host-call\" (func $host-call (param \"kind\" u32) (param \"handle-index\" u32) (result u32)))"
    };
    let lowered_host_call = if host_calls.is_empty() {
        ""
    } else {
        "(core func $host-call-lowered (canon lower (func $host-call)))"
    };
    let module_host_import = if host_calls.is_empty() {
        ""
    } else {
        "(import \"host\" \"host-call\" (func $host-call (param i32 i32) (result i32)))"
    };
    let host_call_instruction = host_calls
        .iter()
        .map(|(kind, handle)| format!("i32.const {kind} i32.const {handle} call $host-call drop"))
        .collect::<Vec<_>>()
        .join(" ");
    let instance_host_export = if host_calls.is_empty() {
        ""
    } else {
        "(export \"host-call\" (func $host-call-lowered))"
    };
    format!(
        "(component
            (import \"output-byte\" (func $output-byte (param \"index\" u32) (param \"value\" u32) (result u32)))
            {component_host_import}
            (core func $output-byte-lowered (canon lower (func $output-byte)))
            {lowered_host_call}
            (core module $module
                (import \"host\" \"output-byte\" (func $output-byte (param i32 i32) (result i32)))
                {module_host_import}
                (func (export \"invoke\") (result i32)
                    {host_call_instruction}
                    {output_instructions}
                    i32.const {length}))
            (core instance $instance (instantiate $module
                (with \"host\" (instance
                    (export \"output-byte\" (func $output-byte-lowered))
                    {instance_host_export}))))
            (func (export \"invoke\") (result u32) (canon lift (core func $instance \"invoke\"))))",
        length = response_frame.len(),
    )
}

fn looping_component_wat(with_memory_growth: bool) -> &'static str {
    if with_memory_growth {
        "(component
            (core module $module
                (memory 1)
                (func (export \"invoke\") (result i32)
                    i32.const 65536 memory.grow drop i32.const 0))
            (core instance $instance (instantiate $module))
            (func (export \"invoke\") (result u32) (canon lift (core func $instance \"invoke\"))))"
    } else {
        "(component
            (core module $module
                (func (export \"invoke\") (result i32)
                    (loop $forever br $forever) i32.const 0))
            (core instance $instance (instantiate $module))
            (func (export \"invoke\") (result u32) (canon lift (core func $instance \"invoke\"))))"
    }
}

fn signalling_loop_component_wat() -> &'static str {
    "(component
        (import \"host-call\" (func $host-call (param \"kind\" u32) (param \"handle-index\" u32) (result u32)))
        (core func $host-call-lowered (canon lower (func $host-call)))
        (core module $module
            (import \"host\" \"host-call\" (func $host-call (param i32 i32) (result i32)))
            (func (export \"invoke\") (result i32)
                i32.const 6 i32.const 0 call $host-call drop
                (loop $forever br $forever)
                i32.const 0))
        (core instance $instance (instantiate $module
            (with \"host\" (instance
                (export \"host-call\" (func $host-call-lowered))))))
        (func (export \"invoke\") (result u32)
            (canon lift (core func $instance \"invoke\"))))"
}

fn two_memory_component_wat(response_frame: &[u8]) -> String {
    let output_instructions = response_frame
        .iter()
        .enumerate()
        .map(|(index, byte)| format!("i32.const {index} i32.const {byte} call $output-byte drop"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "(component
            (import \"output-byte\" (func $output-byte (param \"index\" u32) (param \"value\" u32) (result u32)))
            (core func $output-byte-lowered (canon lower (func $output-byte)))
            (core module $first
                (import \"host\" \"output-byte\" (func $output-byte (param i32 i32) (result i32)))
                (memory 1)
                (func (export \"invoke\") (result i32)
                    {output_instructions}
                    i32.const {length}))
            (core module $second (memory 1))
            (core instance $first-instance (instantiate $first
                (with \"host\" (instance
                    (export \"output-byte\" (func $output-byte-lowered))))))
            (core instance $second-instance (instantiate $second))
            (func (export \"invoke\") (result u32)
                (canon lift (core func $first-instance \"invoke\"))))",
        length = response_frame.len(),
    )
}

#[cfg(unix)]
#[test]
fn isolated_subprocess_sanitizes_environment_and_requires_clean_exit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        b"placeholder",
        "fixture.sh",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let invocation_id = record('1')?;
    let mut provisional = invocation(&placeholder_activated, '1', Duration::from_millis(800))?;
    provisional.invocation_id = invocation_id.clone();
    let response = successful_response(&placeholder_activated, &provisional)?;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let body = format!(
        "if [ \"${{HOME+x}}\" = x ]; then exit 90; fi\nprintf '{}'\nexit 0",
        shell_octal(&frame)
    );
    let (_path, script) = executable_script(directory.path(), &body)?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &script,
        "fixture.sh",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &script,
        &fixture.policy,
    )?;
    let invocation_record = invocation(&activated, '1', Duration::from_millis(800))?;
    assert_eq!(
        raw_content_digest(&script)?,
        activated.manifest().implementation_digest
    );
    let sandbox = SubprocessSandbox::direct_fixture(&activated, directory.path(), Vec::new())?;
    let backend = IsolatedSubprocessBackend::new(sandbox)?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(activated.clone(), Arc::new(backend))?;
    host.invoke(InvocationRequest::new(invocation_record)?)?;

    let crash_body = format!("printf '{}'\nexit 7", shell_octal(&frame));
    let (_path, crash_script) = executable_script(directory.path(), &crash_body)?;
    let crash_fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &crash_script,
        "fixture.sh",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let crash_activated = activate_extension(
        crash_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &crash_script,
        &crash_fixture.policy,
    )?;
    let crash_invocation = invocation(&crash_activated, '1', Duration::from_millis(800))?;
    assert_eq!(
        raw_content_digest(&crash_script)?,
        crash_activated.manifest().implementation_digest
    );
    let sandbox =
        SubprocessSandbox::direct_fixture(&crash_activated, directory.path(), Vec::new())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        crash_activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(crash_invocation,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ExtensionCrashed)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn isolated_subprocess_kills_infinite_loop_and_rejects_output_flood()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let (_path, loop_script) = executable_script(directory.path(), "while :; do :; done")?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &loop_script,
        "fixture.sh",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &loop_script,
        &fixture.policy,
    )?;
    let sandbox = SubprocessSandbox::direct_fixture(&activated, directory.path(), Vec::new())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '1',
            Duration::from_millis(80)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DeadlineExceeded)
    );

    let (_path, flood_script) =
        executable_script(directory.path(), "printf '\\377\\377\\377\\377'\nexit 0")?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &flood_script,
        "fixture.sh",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &flood_script,
        &fixture.policy,
    )?;
    let sandbox = SubprocessSandbox::direct_fixture(&activated, directory.path(), Vec::new())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '2',
            Duration::from_millis(800)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidFrame)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn isolated_subprocess_broker_loop_reads_blob_and_rejects_forged_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let capabilities = vec![ExtensionHostCapability::BlobRead];
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        b"placeholder",
        "fixture.py",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '1', Duration::from_millis(800))?;
    let mut response = successful_response(&placeholder_activated, &provisional)?;
    response.host_call_count = 1;
    let response_frame = FrameCodec::new(65_536)?.encode(&response)?;
    let body = python_blob_call_script(&provisional.invocation_id, &response_frame, false);
    let (_path, script) = executable_python_script(directory.path(), &body)?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &script,
        "fixture.py",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &script,
        &fixture.policy,
    )?;
    let mut invocation_record = invocation(&activated, '1', Duration::from_millis(800))?;
    let broker = Arc::new(CapabilityBroker::new(
        activated.clone(),
        invocation_record.invocation_id.clone(),
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        capabilities.clone(),
        None,
        Vec::new(),
        Arc::new(AllowProtected),
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?);
    invocation_record.handles =
        vec![broker.grant_blob(b"subprocess-blob-canary".to_vec(), Classification::Internal)?];
    invocation_record.validate()?;
    let sandbox = SubprocessSandbox::direct_fixture(&activated, directory.path(), Vec::new())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    host.invoke(InvocationRequest::new(invocation_record)?.with_broker(broker.clone())?)?;
    let transcript = broker.transcript()?;
    assert_eq!(transcript.len(), 1);
    assert_eq!(
        transcript.first().map(|call| call.response.as_slice()),
        Some(b"subprocess-blob-canary".as_slice())
    );

    let forged_provisional = invocation(&placeholder_activated, '2', Duration::from_millis(800))?;
    let forged_response = successful_response(&placeholder_activated, &forged_provisional)?;
    let forged_frame = FrameCodec::new(65_536)?.encode(&forged_response)?;
    let forged_body =
        python_blob_call_script(&forged_provisional.invocation_id, &forged_frame, true);
    let (_path, forged_script) = executable_python_script(directory.path(), &forged_body)?;
    let forged_fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &forged_script,
        "fixture.py",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let forged_activated = activate_extension(
        forged_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &forged_script,
        &forged_fixture.policy,
    )?;
    let mut forged_invocation = invocation(&forged_activated, '2', Duration::from_millis(800))?;
    let forged_broker = Arc::new(CapabilityBroker::new(
        forged_activated.clone(),
        forged_invocation.invocation_id.clone(),
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        capabilities,
        None,
        Vec::new(),
        Arc::new(AllowProtected),
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?);
    forged_invocation.handles =
        vec![forged_broker.grant_blob(b"real-blob".to_vec(), Classification::Internal)?];
    let sandbox =
        SubprocessSandbox::direct_fixture(&forged_activated, directory.path(), Vec::new())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        forged_activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(forged_invocation)?.with_broker(forged_broker)?,)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_bubblewrap_denies_ambient_authority_process_creation_and_trusted_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(bubblewrap) = [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")]
        .into_iter()
        .find(|path| path.is_file())
    else {
        eprintln!("skipped: bubblewrap is not installed at a supported Tier-1 path");
        return Ok(());
    };
    let preflight = std::process::Command::new(bubblewrap)
        .arg("--die-with-parent")
        .arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-net")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--new-session")
        .arg("--clearenv")
        .arg("--cap-drop")
        .arg("ALL")
        .arg("--uid")
        .arg("65534")
        .arg("--gid")
        .arg("65534")
        .arg("--ro-bind")
        .arg("/")
        .arg("/")
        .arg("--")
        .arg("/bin/true")
        .env_clear()
        .output();
    match preflight {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!(
                "skipped: bubblewrap is installed but unusable with the required namespaces: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return Ok(());
        }
        Err(failure) => {
            eprintln!("skipped: bubblewrap is installed but cannot be launched: {failure}");
            return Ok(());
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        b"placeholder",
        "probe",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '9', Duration::from_millis(1_900))?;
    let codec = FrameCodec::new(65_536)?;
    let mutation_call = codec.encode_value(&GuestHostCallRequest {
        invocation_id: provisional.invocation_id.clone(),
        ordinal: 1,
        kind: cigar_protocol::ExtensionHostCallKind::FileWrite,
        handle: Some(cigar_protocol::ExtensionHandle::new([0xA5; 32])),
        request: b"forged trusted-state mutation".to_vec(),
    })?;
    let mut response = successful_response(&placeholder_activated, &provisional)?;
    response.host_call_count = 1;
    let response = codec.encode(&response)?;
    let c_array = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    let directory = tempfile::tempdir()?;
    let source = directory.path().join("probe.c");
    let executable = directory.path().join("probe");
    let trusted_state = directory.path().join("trusted-state");
    fs::write(&trusted_state, b"trusted-state-unchanged")?;
    let trusted_state_path = trusted_state
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(
        &source,
        format!(
            r#"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const unsigned char HOST_CALL[] = {{{host_call}}};
static const unsigned char RESPONSE[] = {{{response}}};

static int read_exact(int fd, unsigned char *buffer, size_t length) {{
  size_t offset = 0;
  while (offset < length) {{
    ssize_t amount = read(fd, buffer + offset, length - offset);
    if (amount <= 0) return -1;
    offset += (size_t)amount;
  }}
  return 0;
}}

static int discard_frame(void) {{
  unsigned char prefix[4];
  unsigned char buffer[4096];
  if (read_exact(STDIN_FILENO, prefix, sizeof(prefix)) != 0) return -1;
  uint32_t remaining = ((uint32_t)prefix[0] << 24) | ((uint32_t)prefix[1] << 16) |
                       ((uint32_t)prefix[2] << 8) | (uint32_t)prefix[3];
  if (remaining > 1048576U) return -1;
  while (remaining > 0) {{
    size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
    if (read_exact(STDIN_FILENO, buffer, chunk) != 0) return -1;
    remaining -= (uint32_t)chunk;
  }}
  return 0;
}}

static int write_exact(const unsigned char *buffer, size_t length) {{
  size_t offset = 0;
  while (offset < length) {{
    ssize_t amount = write(STDOUT_FILENO, buffer + offset, length - offset);
    if (amount <= 0) return -1;
    offset += (size_t)amount;
  }}
  return 0;
}}

int main(void) {{
  if (discard_frame() != 0) return 20;
  int file = open("/etc/passwd", O_RDONLY);
  if (file >= 0) {{ close(file); return 11; }}
  file = open("{trusted_state_path}", O_WRONLY | O_TRUNC);
  if (file >= 0) {{
    (void)write(file, "mutated", 7);
    close(file);
    return 12;
  }}
  file = open("/cigar/forbidden", O_WRONLY | O_CREAT, 0600);
  if (file >= 0) {{ close(file); return 17; }}

  int network = socket(AF_INET, SOCK_STREAM, 0);
  if (network >= 0) {{
    struct sockaddr_in address = {{0}};
    address.sin_family = AF_INET;
    address.sin_port = htons({port});
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(network, (struct sockaddr *)&address, sizeof(address)) == 0) return 13;
    close(network);
  }}
  if (getenv("HOME") != NULL || getenv("CIGAR_SECRET_CANARY") != NULL) return 14;

  errno = 0;
  pid_t child = fork();
  if (child >= 0) {{
    if (child == 0) _exit(15);
    (void)waitpid(child, NULL, 0);
    return 15;
  }}
  if (errno != EAGAIN) return 16;

  if (write_exact(HOST_CALL, sizeof(HOST_CALL)) != 0) return 21;
  if (discard_frame() != 0) return 22;
  if (write_exact(RESPONSE, sizeof(RESPONSE)) != 0) return 23;
  return 0;
}}
"#,
            host_call = c_array(&mutation_call),
            response = c_array(&response),
            trusted_state_path = trusted_state_path,
        ),
    )?;
    let compiler = std::process::Command::new("cc")
        .arg("-O2")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()?;
    if !compiler.status.success() {
        return Err(format!(
            "failed to compile Linux sandbox probe: {}",
            String::from_utf8_lossy(&compiler.stderr)
        )
        .into());
    }

    let implementation = fs::read(&executable)?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::IsolatedSubprocess,
        &implementation,
        "probe",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &implementation,
        &fixture.policy,
    )?;
    let sandbox = SubprocessSandbox::for_current_platform(&activated, directory.path())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(IsolatedSubprocessBackend::new(sandbox)?),
    )?;
    let trusted_state_mutated = AtomicBool::new(false);
    let result = host.invoke(InvocationRequest::new(invocation(
        &activated,
        '9',
        Duration::from_millis(1_900),
    )?)?);
    if result.is_ok() {
        trusted_state_mutated.store(true, Ordering::SeqCst);
    }
    assert_eq!(
        result.err().map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    assert!(!trusted_state_mutated.load(Ordering::SeqCst));
    assert_eq!(fs::read(trusted_state)?, b"trusted-state-unchanged");
    Ok(())
}

#[test]
fn wasi_component_executes_without_ambient_imports_and_denies_memory_growth()
-> Result<(), Box<dyn std::error::Error>> {
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '1', Duration::from_millis(800))?;
    let response = successful_response(&placeholder_activated, &provisional)?;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let component = wat::parse_str(component_output_wat(&frame, None))?;
    let mut debug_config = wasmtime::Config::new();
    debug_config
        .wasm_component_model(true)
        .consume_fuel(true)
        .epoch_interruption(true);
    let debug_engine = wasmtime::Engine::new(&debug_config)?;
    wasmtime::component::Component::new(&debug_engine, &component)
        .map_err(|failure| format!("fixture component does not compile: {failure:?}"))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    let backend = WasiPreview2Backend::new(activated.clone(), component)
        .map_err(|failure| format!("component backend construction failed: {failure:?}"))?;
    host.register(activated.clone(), Arc::new(backend))?;
    host.invoke(InvocationRequest::new(invocation(
        &activated,
        '1',
        Duration::from_millis(800),
    )?)?)
    .map_err(|failure| format!("component invocation failed: {failure:?}"))?;

    let ambient = wat::parse_str(
        "(component
            (import \"wasi:random/random@0.2.0\" (instance $random
                (export \"get-random-u64\" (func (result u64)))))
            (core module $module
                (func (export \"invoke\") (result i32) i32.const 0))
            (core instance $instance (instantiate $module))
            (func (export \"invoke\") (result u32) (canon lift (core func $instance \"invoke\"))))",
    )?;
    let ambient_fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &ambient,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let ambient_activated = activate_extension(
        ambient_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &ambient,
        &ambient_fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        ambient_activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            ambient_activated.clone(),
            ambient,
        )?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &ambient_activated,
            '2',
            Duration::from_millis(800)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );

    let growth = wat::parse_str(looping_component_wat(true))?;
    let growth_fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &growth,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let growth_activated = activate_extension(
        growth_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &growth,
        &growth_fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        growth_activated.clone(),
        Arc::new(WasiPreview2Backend::new(growth_activated.clone(), growth)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &growth_activated,
            '3',
            Duration::from_millis(800)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn wasi_component_compiles_once_at_activation_and_reuses_the_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '1', Duration::from_millis(800))?;
    let response = successful_response(&placeholder_activated, &provisional)?;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let component = wat::parse_str(component_output_wat(&frame, None))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    let backend = Arc::new(WasiPreview2Backend::new(activated.clone(), component)?);
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(activated.clone(), backend.clone())?;
    for _ in 0..2 {
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '1',
            Duration::from_millis(800),
        )?)?)?;
    }
    assert_eq!(backend.compilation_count(), 1);
    Ok(())
}

#[test]
fn wasi_shared_compiled_engine_keeps_invocation_cancellation_isolated()
-> Result<(), Box<dyn std::error::Error>> {
    let component = wat::parse_str(signalling_loop_component_wat())?;
    let mut fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        vec![ExtensionHostCapability::StructuredTracing],
        None,
        None,
        2,
    )?;
    fixture.manifest.limits.compute = ExtensionComputeBudget::Fuel {
        units: MAX_EXTENSION_FUEL,
    };
    fixture.policy.maximum_limits.compute = ExtensionComputeBudget::Fuel {
        units: MAX_EXTENSION_FUEL,
    };
    resign(&mut fixture.manifest, &fixture.secret)?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    let host = Arc::new(ExtensionHost::new(Arc::new(SystemHostClock)));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(activated.clone(), component)?),
    )?;

    let first_broker = Arc::new(broker(activated.clone(), '1', Arc::new(AllowProtected))?);
    let second_broker = Arc::new(broker(activated.clone(), '2', Arc::new(AllowProtected))?);
    let first_request =
        InvocationRequest::new(invocation(&activated, '1', Duration::from_millis(800))?)?
            .with_broker(first_broker.clone())?;
    let second_request =
        InvocationRequest::new(invocation(&activated, '2', Duration::from_millis(800))?)?
            .with_broker(second_broker.clone())?;
    let first_cancellation = first_request.cancellation();
    let second_cancellation = second_request.cancellation();
    let first_host = host.clone();
    let first_worker = thread::spawn(move || first_host.invoke(first_request));
    let second_host = host.clone();
    let second_worker = thread::spawn(move || second_host.invoke(second_request));

    let entry_deadline = Instant::now() + Duration::from_millis(500);
    while (first_broker.host_call_count() == 0 || second_broker.host_call_count() == 0)
        && Instant::now() < entry_deadline
    {
        thread::sleep(Duration::from_millis(1));
    }
    if first_broker.host_call_count() == 0 || second_broker.host_call_count() == 0 {
        first_cancellation.cancel();
        second_cancellation.cancel();
        let _first_result = first_worker.join();
        let _second_result = second_worker.join();
        return Err("concurrent components did not enter guest execution".into());
    }

    first_cancellation.cancel();
    let first_result = first_worker
        .join()
        .map_err(|_panic| "first component worker panicked")?;
    thread::sleep(Duration::from_millis(20));
    let second_finished_early = second_worker.is_finished();
    second_cancellation.cancel();
    let second_result = second_worker
        .join()
        .map_err(|_panic| "second component worker panicked")?;
    assert_eq!(
        first_result.err().map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::Cancelled)
    );
    assert!(!second_finished_early);
    assert_eq!(
        second_result.err().map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::Cancelled)
    );
    Ok(())
}

#[test]
fn wasi_component_enforces_one_aggregate_budget_across_multiple_memories()
-> Result<(), Box<dyn std::error::Error>> {
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '2', Duration::from_millis(800))?;
    let response = successful_response(&placeholder_activated, &provisional)?;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let component = wat::parse_str(two_memory_component_wat(&frame))?;
    let mut fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    fixture.manifest.limits.max_memory_bytes = 65_536;
    resign(&mut fixture.manifest, &fixture.secret)?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            activated.clone(),
            component.clone(),
        )?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '2',
            Duration::from_millis(800),
        )?)?)
        .err()
        .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );

    let mut allowed_fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    allowed_fixture.manifest.limits.max_memory_bytes = 2 * 65_536;
    resign(&mut allowed_fixture.manifest, &allowed_fixture.secret)?;
    let allowed_activated = activate_extension(
        allowed_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &allowed_fixture.policy,
    )?;
    let allowed_host = ExtensionHost::new(Arc::new(SystemHostClock));
    allowed_host.register(
        allowed_activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            allowed_activated.clone(),
            component,
        )?),
    )?;
    allowed_host.invoke(InvocationRequest::new(invocation(
        &allowed_activated,
        '2',
        Duration::from_millis(800),
    )?)?)?;
    Ok(())
}

#[test]
fn wasi_component_rejects_shared_memory_that_bypasses_resource_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let component = wat::parse_str(
        "(component
            (core module $module
                (memory 1 1 shared)
                (func (export \"invoke\") (result i32) i32.const 0))
            (core instance $instance (instantiate $module))
            (func (export \"invoke\") (result u32)
                (canon lift (core func $instance \"invoke\"))))",
    )?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    assert_eq!(
        WasiPreview2Backend::new(activated, component)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn wasi_transcript_exhaustion_surfaces_resource_exhausted_without_losing_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = vec![ExtensionHostCapability::StructuredTracing];
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '3', Duration::from_millis(800))?;
    let mut response = successful_response(&placeholder_activated, &provisional)?;
    response.host_call_count = 1;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let component = wat::parse_str(component_output_wat_with_calls(&frame, &[(6, 0), (6, 0)]))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        capabilities,
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;

    let probe = broker(activated.clone(), '4', Arc::new(AllowProtected))?;
    probe.dispatch_host_call(cigar_protocol::ExtensionHostCallKind::Trace, None, &[])?;
    let one_call_bytes = probe.retained_transcript_bytes_for_test()?;
    drop(probe);

    let mut broker = broker(activated.clone(), '3', Arc::new(AllowProtected))?;
    broker.set_maximum_transcript_bytes_for_test(
        one_call_bytes
            // Wall-clock timestamp rendering can vary by a few bytes between the probe and the
            // real call. Leave enough room for that representation variance, but far less than
            // the conservative 4 KiB reservation required by a second call.
            .checked_add(64)
            .ok_or("transcript fixture limit overflowed")?
            .max(4_098),
    );
    let broker = Arc::new(broker);
    let invocation_record = invocation(&activated, '3', Duration::from_millis(800))?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(activated, component)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation_record)?.with_broker(broker.clone())?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );
    assert_eq!(broker.host_call_count(), 1);
    assert_eq!(broker.transcript()?.len(), 1);
    Ok(())
}

#[test]
fn wasi_component_broker_call_reads_blob_and_forbidden_handle_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = vec![ExtensionHostCapability::BlobRead];
    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '1', Duration::from_millis(800))?;
    let mut response = successful_response(&placeholder_activated, &provisional)?;
    response.host_call_count = 1;
    let frame = FrameCodec::new(65_536)?.encode(&response)?;
    let component = wat::parse_str(component_output_wat(&frame, Some((2, 0))))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &component,
        "component.wasm",
        capabilities,
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &component,
        &fixture.policy,
    )?;
    let mut invocation_record = invocation(&activated, '1', Duration::from_millis(800))?;
    let broker = Arc::new(CapabilityBroker::new(
        activated.clone(),
        invocation_record.invocation_id.clone(),
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        vec![ExtensionHostCapability::BlobRead],
        None,
        Vec::new(),
        Arc::new(AllowProtected),
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?);
    let handle = broker.grant_blob(b"brokered-blob-canary".to_vec(), Classification::Internal)?;
    invocation_record.handles = vec![handle];
    invocation_record.validate()?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(activated.clone(), component)?),
    )?;
    host.invoke(InvocationRequest::new(invocation_record)?.with_broker(broker.clone())?)?;
    let transcript = broker.transcript()?;
    assert_eq!(transcript.len(), 1);
    assert_eq!(
        transcript.first().map(|call| call.response.as_slice()),
        Some(b"brokered-blob-canary".as_slice())
    );

    let forbidden_response = successful_response(
        &placeholder_activated,
        &invocation(&placeholder_activated, '2', Duration::from_millis(800))?,
    )?;
    let forbidden_frame = FrameCodec::new(65_536)?.encode(&forbidden_response)?;
    let forbidden_component =
        wat::parse_str(component_output_wat(&forbidden_frame, Some((2, 999))))?;
    let forbidden_fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &forbidden_component,
        "component.wasm",
        vec![ExtensionHostCapability::BlobRead],
        None,
        None,
        1,
    )?;
    let forbidden_activated = activate_extension(
        forbidden_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &forbidden_component,
        &forbidden_fixture.policy,
    )?;
    let forbidden_invocation = invocation(&forbidden_activated, '2', Duration::from_millis(800))?;
    let forbidden_broker = Arc::new(CapabilityBroker::new(
        forbidden_activated.clone(),
        forbidden_invocation.invocation_id.clone(),
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        vec![ExtensionHostCapability::BlobRead],
        None,
        Vec::new(),
        Arc::new(AllowProtected),
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?);
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        forbidden_activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            forbidden_activated.clone(),
            forbidden_component,
        )?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(forbidden_invocation)?.with_broker(forbidden_broker)?,)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    Ok(())
}

#[test]
fn wasi_forged_state_mutation_has_no_outcome_and_preserves_trusted_state()
-> Result<(), Box<dyn std::error::Error>> {
    let trusted = tempfile::tempdir()?;
    let trusted_state = trusted.path().join("trusted-state");
    fs::write(&trusted_state, b"trusted-state-unchanged")?;

    let placeholder = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        b"placeholder",
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let placeholder_activated = activate_extension(
        placeholder.manifest.clone(),
        PACKAGE_BYTES,
        b"placeholder",
        &placeholder.policy,
    )?;
    let provisional = invocation(&placeholder_activated, '4', Duration::from_millis(800))?;
    let response = successful_response(&placeholder_activated, &provisional)?;
    let response_frame = FrameCodec::new(65_536)?.encode(&response)?;
    let hostile_component = wat::parse_str(component_output_wat(&response_frame, Some((10, 999))))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &hostile_component,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &hostile_component,
        &fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            activated.clone(),
            hostile_component,
        )?),
    )?;

    let trusted_commit_advanced = AtomicBool::new(false);
    let result = host.invoke(InvocationRequest::new(invocation(
        &activated,
        '4',
        Duration::from_millis(800),
    )?)?);
    if result.is_ok() {
        trusted_commit_advanced.store(true, Ordering::SeqCst);
    }
    assert_eq!(
        result.err().map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::CapabilityDenied)
    );
    assert!(!trusted_commit_advanced.load(Ordering::SeqCst));
    assert_eq!(fs::read(trusted_state)?, b"trusted-state-unchanged");
    Ok(())
}

#[test]
fn wasi_component_fuel_and_epoch_stop_infinite_loop() -> Result<(), Box<dyn std::error::Error>> {
    let looping = wat::parse_str(looping_component_wat(false))?;
    let fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &looping,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    let activated = activate_extension(
        fixture.manifest.clone(),
        PACKAGE_BYTES,
        &looping,
        &fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        activated.clone(),
        Arc::new(WasiPreview2Backend::new(
            activated.clone(),
            looping.clone(),
        )?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &activated,
            '1',
            Duration::from_millis(800)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::ResourceExhausted)
    );

    let mut epoch_fixture = signed_fixture(
        ExtensionRuntimeKind::WasiPreview2,
        &looping,
        "component.wasm",
        Vec::new(),
        None,
        None,
        1,
    )?;
    epoch_fixture.manifest.limits.compute = ExtensionComputeBudget::Fuel {
        units: 1_000_000_000_000,
    };
    epoch_fixture.policy.maximum_limits.compute = epoch_fixture.manifest.limits.compute;
    resign(&mut epoch_fixture.manifest, &epoch_fixture.secret)?;
    let epoch_activated = activate_extension(
        epoch_fixture.manifest.clone(),
        PACKAGE_BYTES,
        &looping,
        &epoch_fixture.policy,
    )?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(
        epoch_activated.clone(),
        Arc::new(WasiPreview2Backend::new(epoch_activated.clone(), looping)?),
    )?;
    assert_eq!(
        host.invoke(InvocationRequest::new(invocation(
            &epoch_activated,
            '2',
            Duration::from_millis(30)
        )?,)?)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DeadlineExceeded)
    );
    Ok(())
}

struct FixtureRemoteBridge {
    identity: Mutex<RemoteIdentity>,
    inbound: Mutex<VecDeque<Vec<u8>>>,
    exchanges: AtomicU32,
    identity_reads: AtomicU32,
}

impl AuthenticatedRemoteBridge for FixtureRemoteBridge {
    fn identity(&self) -> Result<RemoteIdentity, ExtensionHostError> {
        self.identity_reads.fetch_add(1, Ordering::SeqCst);
        self.identity
            .lock()
            .map(|identity| identity.clone())
            .map_err(|_error| ExtensionHostError::new(ExtensionHostErrorCode::BackendUnavailable))
    }

    fn exchange(
        &self,
        framed_request: &[u8],
        deadline: Instant,
        cancellation: InvocationCancellation,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError> {
        if framed_request.is_empty() || cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err(ExtensionHostError::new(
                ExtensionHostErrorCode::DeadlineExceeded,
            ));
        }
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        let response = self
            .inbound
            .lock()
            .map_err(|_error| ExtensionHostError::new(ExtensionHostErrorCode::BackendUnavailable))?
            .pop_front()
            .ok_or_else(|| ExtensionHostError::new(ExtensionHostErrorCode::ExtensionCrashed))?;
        if response.len() > maximum_response_bytes {
            return Err(ExtensionHostError::new(
                ExtensionHostErrorCode::ResourceExhausted,
            ));
        }
        Ok(response)
    }
}

#[test]
fn remote_bridge_reauthenticates_and_runs_the_same_broker_loop()
-> Result<(), Box<dyn std::error::Error>> {
    let capabilities = vec![ExtensionHostCapability::BlobRead];
    let fixture = signed_fixture(
        ExtensionRuntimeKind::RemoteGrpc,
        DEFAULT_IMPLEMENTATION,
        "cigar.v1/invoke",
        capabilities.clone(),
        None,
        None,
        1,
    )?;
    let activated = activate(&fixture)?;
    let mut invocation_record = invocation(&activated, '1', Duration::from_millis(800))?;
    let broker = Arc::new(CapabilityBroker::new(
        activated.clone(),
        invocation_record.invocation_id.clone(),
        ExtensionKind::Transform,
        "transform.fixture",
        "processor.fixture",
        capabilities,
        None,
        Vec::new(),
        Arc::new(AllowProtected),
        Arc::new(EchoNetwork),
        Arc::new(EchoSecret),
        Arc::new(SystemHostClock),
    )?);
    let handle = broker.grant_blob(b"remote-blob-canary".to_vec(), Classification::Internal)?;
    invocation_record.handles = vec![handle.clone()];
    let mut response = successful_response(&activated, &invocation_record)?;
    response.host_call_count = 1;
    let codec = FrameCodec::new(65_536)?;
    let call = codec.encode_value(&GuestHostCallRequest {
        invocation_id: invocation_record.invocation_id.clone(),
        ordinal: 1,
        kind: cigar_protocol::ExtensionHostCallKind::ReadBlob,
        handle: Some(handle),
        request: Vec::new(),
    })?;
    let response = codec.encode(&response)?;
    let peer_digest = raw_content_digest(b"authenticated-mtls-peer")?;
    let identity = RemoteIdentity {
        extension_id: activated.manifest().extension_id.clone(),
        manifest_digest: activated.manifest_digest().clone(),
        implementation_digest: activated.manifest().implementation_digest.clone(),
        package_digest: activated.manifest().package_digest.clone(),
        protocol_abi: version(),
        authenticated_peer_digest: peer_digest.clone(),
    };
    let bridge = Arc::new(FixtureRemoteBridge {
        identity: Mutex::new(identity.clone()),
        inbound: Mutex::new(VecDeque::from([call, response])),
        exchanges: AtomicU32::new(0),
        identity_reads: AtomicU32::new(0),
    });
    let backend = RemoteGrpcBackend::new(activated.clone(), peer_digest.clone(), bridge.clone())?;
    let host = ExtensionHost::new(Arc::new(SystemHostClock));
    host.register(activated.clone(), Arc::new(backend))?;
    host.invoke(InvocationRequest::new(invocation_record)?.with_broker(broker.clone())?)?;
    assert_eq!(bridge.exchanges.load(Ordering::SeqCst), 2);
    assert_eq!(bridge.identity_reads.load(Ordering::SeqCst), 3);
    assert_eq!(
        broker
            .transcript()?
            .first()
            .map(|call| call.response.as_slice()),
        Some(b"remote-blob-canary".as_slice())
    );

    let wrong_peer = Arc::new(FixtureRemoteBridge {
        identity: Mutex::new(RemoteIdentity {
            authenticated_peer_digest: raw_content_digest(b"wrong-peer")?,
            ..identity
        }),
        inbound: Mutex::new(VecDeque::new()),
        exchanges: AtomicU32::new(0),
        identity_reads: AtomicU32::new(0),
    });
    assert_eq!(
        RemoteGrpcBackend::new(activated, peer_digest, wrong_peer)
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::RemoteAuthenticationFailed)
    );
    Ok(())
}

#[test]
fn successful_backend_smoke_test() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        2,
    )?;
    let activated = activate(&fixture)?;
    let (host, backend) = host_with_backend(activated.clone(), BackendBehavior::Success)?;
    host.invoke(InvocationRequest::new(invocation(
        &activated,
        '1',
        Duration::from_secs(1),
    )?)?)?;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn deterministic_vector_runner_uses_fresh_threads_and_rejects_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture(
        ExtensionRuntimeKind::BuiltIn,
        DEFAULT_IMPLEMENTATION,
        "bin/fixture",
        Vec::new(),
        None,
        None,
        8,
    )?;
    let activated = activate(&fixture)?;
    let template = invocation(&activated, '1', Duration::from_secs(1))?;
    let expected = successful_response(&activated, &template)?;
    let vector = DeterminismVector::new(&template, &expected)?;
    let runner = DeterministicVectorRunner::new(5, [7; 32])?;
    let (host, backend) = host_with_backend(activated.clone(), BackendBehavior::Success)?;
    let report = runner.run(&host, &vector, |_launch| {
        InvocationRequest::new(template.clone())
    })?;
    assert_eq!(report.launches(), 5);
    assert_eq!(
        report.output_digest(),
        expected.output_digest.as_ref().ok_or("digest")?
    );
    assert_eq!(report.host_call_count(), 0);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 5);

    let mut drifted = expected;
    drifted.output = b"drifted semantic output".to_vec();
    drifted.output_digest = Some(raw_content_digest(&drifted.output)?);
    let drift_vector = DeterminismVector::new(&template, &drifted)?;
    let drift_runner = DeterministicVectorRunner::new(2, [8; 32])?;
    assert_eq!(
        drift_runner
            .run(&host, &drift_vector, |_launch| {
                InvocationRequest::new(template.clone())
            })
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::DigestMismatch)
    );
    assert!(DeterministicVectorRunner::new(1, [0; 32]).is_err());
    assert!(DeterministicVectorRunner::new(65, [0; 32]).is_err());

    let mut nondeterministic = fixture.manifest;
    nondeterministic.determinism = ExtensionDeterminism::Nondeterministic;
    resign(&mut nondeterministic, &fixture.secret)?;
    let activated = activate_extension(
        nondeterministic,
        PACKAGE_BYTES,
        DEFAULT_IMPLEMENTATION,
        &fixture.policy,
    )?;
    let template = invocation(&activated, '2', Duration::from_secs(1))?;
    let expected = successful_response(&activated, &template)?;
    let vector = DeterminismVector::new(&template, &expected)?;
    let (host, _) = host_with_backend(activated, BackendBehavior::Success)?;
    assert_eq!(
        runner
            .run(&host, &vector, |_launch| {
                InvocationRequest::new(template.clone())
            })
            .err()
            .map(ExtensionHostError::code),
        Some(ExtensionHostErrorCode::InvalidInput)
    );
    Ok(())
}
