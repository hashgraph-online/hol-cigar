//! Authenticated remote bridge using the same canonical logical ABI as local runtimes.

use crate::broker::CapabilityBroker;
use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use crate::frame::FrameCodec;
use crate::host::{ExtensionBackend, InvocationCancellation, RuntimeResponse};
use crate::manifest::ActivatedExtension;
use crate::subprocess::{
    GuestMessage, HostCallReply, cumulative_limit, handle_shape_valid, wire_error_code,
};
use cigar_canon::MAX_CANONICAL_INPUT_BYTES;
use cigar_protocol::{
    ContentDigest, ExtensionId, ExtensionInvocationV1, ExtensionRuntimeKind,
    ExtensionSemanticVersion,
};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

/// Authenticated peer identity bound to an exact activated implementation and ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteIdentity {
    /// Extension identity asserted by the authenticated transport peer.
    pub extension_id: ExtensionId,
    /// Signature-excluded manifest digest presented by the peer.
    pub manifest_digest: ContentDigest,
    /// Exact implementation digest presented by the peer.
    pub implementation_digest: ContentDigest,
    /// Exact package digest presented by the peer.
    pub package_digest: ContentDigest,
    /// Exact logical ABI version spoken by the peer.
    pub protocol_abi: ExtensionSemanticVersion,
    /// Digest of the authenticated transport credential or certificate.
    pub authenticated_peer_digest: ContentDigest,
}

/// Injectable mTLS or equivalent authenticated transport for the remote gRPC profile.
pub trait AuthenticatedRemoteBridge: Send + Sync {
    /// Returns the peer identity established by the current authenticated channel.
    fn identity(&self) -> Result<RemoteIdentity, ExtensionHostError>;

    /// Exchanges one canonical length-delimited request and response before the deadline.
    fn exchange(
        &self,
        framed_request: &[u8],
        deadline: Instant,
        cancellation: InvocationCancellation,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ExtensionHostError>;
}

/// Remote gRPC logical-ABI backend with per-call authenticated identity revalidation.
pub struct RemoteGrpcBackend {
    activated: ActivatedExtension,
    bridge: Arc<dyn AuthenticatedRemoteBridge>,
    codec: FrameCodec,
    expected_peer_digest: ContentDigest,
}

impl fmt::Debug for RemoteGrpcBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteGrpcBackend")
            .field("extension_id", &self.activated.manifest().extension_id)
            .field("manifest_digest", self.activated.manifest_digest())
            .field("expected_peer_digest", &self.expected_peer_digest)
            .finish_non_exhaustive()
    }
}

impl RemoteGrpcBackend {
    /// Binds an authenticated bridge to one activated remote manifest and peer credential.
    pub fn new(
        activated: ActivatedExtension,
        expected_peer_digest: ContentDigest,
        bridge: Arc<dyn AuthenticatedRemoteBridge>,
    ) -> Result<Self, ExtensionHostError> {
        if activated.manifest().runtime != ExtensionRuntimeKind::RemoteGrpc {
            return Err(error(ExtensionHostErrorCode::InvalidInput));
        }
        let backend = Self {
            activated,
            bridge,
            codec: FrameCodec::new(MAX_CANONICAL_INPUT_BYTES)?,
            expected_peer_digest,
        };
        backend.verify_identity()?;
        Ok(backend)
    }

    fn verify_identity(&self) -> Result<(), ExtensionHostError> {
        let identity = self.bridge.identity()?;
        let manifest = self.activated.manifest();
        if identity.extension_id != manifest.extension_id
            || &identity.manifest_digest != self.activated.manifest_digest()
            || identity.implementation_digest != manifest.implementation_digest
            || identity.package_digest != manifest.package_digest
            || identity.authenticated_peer_digest != self.expected_peer_digest
            || identity.protocol_abi < manifest.protocol_abi.minimum
            || identity.protocol_abi > manifest.protocol_abi.maximum
        {
            return Err(error(ExtensionHostErrorCode::RemoteAuthenticationFailed));
        }
        Ok(())
    }
}

impl ExtensionBackend for RemoteGrpcBackend {
    fn runtime_kind(&self) -> ExtensionRuntimeKind {
        ExtensionRuntimeKind::RemoteGrpc
    }

    fn invoke(
        &self,
        invocation: &ExtensionInvocationV1,
        deadline: Instant,
        cancellation: InvocationCancellation,
        broker: Option<Arc<CapabilityBroker>>,
    ) -> Result<RuntimeResponse, ExtensionHostError> {
        if cancellation.is_cancelled() {
            return Err(error(ExtensionHostErrorCode::Cancelled));
        }
        if !invocation.authorized_capabilities.is_empty() && broker.is_none() {
            return Err(error(ExtensionHostErrorCode::CapabilityDenied));
        }
        let mut outbound = self.codec.encode(invocation)?;
        let maximum_cumulative = cumulative_limit(invocation)?;
        let mut cumulative = outbound.len();
        let mut calls = 0_u32;
        let mut denied_host_call = false;
        loop {
            if cancellation.is_cancelled() {
                return Err(error(ExtensionHostErrorCode::Cancelled));
            }
            if Instant::now() >= deadline {
                return Err(error(ExtensionHostErrorCode::DeadlineExceeded));
            }
            self.verify_identity()?;
            let inbound = self.bridge.exchange(
                &outbound,
                deadline,
                cancellation.clone(),
                self.codec.maximum_payload_bytes().saturating_add(4),
            )?;
            cumulative = cumulative
                .checked_add(inbound.len())
                .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
            if cumulative > maximum_cumulative {
                return Err(error(ExtensionHostErrorCode::ResourceExhausted));
            }
            match self.codec.decode_value::<GuestMessage>(&inbound)? {
                GuestMessage::Response(response) => {
                    if denied_host_call {
                        return Err(error(ExtensionHostErrorCode::CapabilityDenied));
                    }
                    return Ok(RuntimeResponse::completed(response));
                }
                GuestMessage::HostCall(call) => {
                    calls = calls
                        .checked_add(1)
                        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                    if calls > invocation.effective_limits.max_host_calls
                        || call.invocation_id != invocation.invocation_id
                        || call.ordinal != calls
                        || !handle_shape_valid(call.kind, call.handle.as_ref())
                    {
                        return Err(error(ExtensionHostErrorCode::InvalidFrame));
                    }
                    let result = broker
                        .as_deref()
                        .ok_or_else(|| error(ExtensionHostErrorCode::CapabilityDenied))
                        .and_then(|broker| {
                            broker.dispatch_host_call(
                                call.kind,
                                call.handle.as_ref(),
                                &call.request,
                            )
                        });
                    let (error_code, response) = match result {
                        Ok(response) => (0, response),
                        Err(failure) => {
                            denied_host_call = true;
                            (wire_error_code(failure.code()), Vec::new())
                        }
                    };
                    outbound = self.codec.encode_value(&HostCallReply {
                        invocation_id: invocation.invocation_id.clone(),
                        ordinal: call.ordinal,
                        error_code,
                        response,
                    })?;
                    cumulative = cumulative
                        .checked_add(outbound.len())
                        .ok_or_else(|| error(ExtensionHostErrorCode::ResourceExhausted))?;
                    if cumulative > maximum_cumulative {
                        return Err(error(ExtensionHostErrorCode::ResourceExhausted));
                    }
                }
            }
        }
    }
}
