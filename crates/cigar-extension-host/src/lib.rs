//! Signed extension manifests, isolation, capabilities, resource limits, and host calls.

mod broker;
mod clock;
mod digest;
mod error;
mod frame;
mod host;
mod manifest;
mod remote;
mod subprocess;
mod vector;
mod wasi;

pub use broker::{
    BrokerCallContext, CapabilityBroker, FinalSecretBoundary, NetworkBoundary,
    ProtectedDataAuthorization, ProtectedDataPolicy,
};
pub use clock::{HostClock, SystemHostClock};
pub use error::{ExtensionHostError, ExtensionHostErrorCode};
pub use frame::FrameCodec;
pub use host::{
    ExtensionBackend, ExtensionHost, InvocationCancellation, InvocationOutcome, InvocationRequest,
    RuntimeResponse, extension_response_digest, host_call_transcript_digest,
};
pub use manifest::{ActivatedExtension, ActivationPolicy, activate_extension};
pub use remote::{AuthenticatedRemoteBridge, RemoteGrpcBackend, RemoteIdentity};
pub use subprocess::{IsolatedSubprocessBackend, SubprocessSandbox};
pub use vector::{
    DeterminismVector, DeterminismVectorReport, DeterministicVectorRunner,
    MAX_DETERMINISM_VECTOR_LAUNCHES,
};
pub use wasi::WasiPreview2Backend;

#[cfg(test)]
mod tests;
