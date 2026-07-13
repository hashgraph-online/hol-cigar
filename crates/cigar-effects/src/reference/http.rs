use super::support::{
    MAX_REFERENCE_BODY_BYTES, digest_parts, stable_evidence, validate_bounded_text,
    validate_selector,
};
use crate::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation, EffectConnector,
    EffectError, EffectErrorCode, PreconditionReport, ReconcileObservation,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_protocol::{ContentDigest, IdempotencyKey, RecordId, UtcTimestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

const SEND: &str = "send";
const PROTECTED_ARGUMENT_SCHEMA: &str = "cigar.effect-arguments.idempotent-http.v2";
const MAX_PROTECTED_ARGUMENT_BYTES: usize = 1_400_000;
const MAX_RESOLVED_TARGET_ADDRESSES: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpArgumentDocument {
    schema_version: String,
    method: String,
    content_type: String,
    body_base64url: String,
    project_id: String,
    resource_id: String,
}

/// Typed external object selector included in both authorization and transport semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResourceScope {
    project_id: RecordId,
    resource_id: String,
}

impl HttpResourceScope {
    /// Creates one canonical project/resource selector.
    pub fn new(project_id: RecordId, resource_id: impl Into<String>) -> Result<Self, EffectError> {
        let resource_id = resource_id.into();
        validate_selector(&resource_id)?;
        Ok(Self {
            project_id,
            resource_id,
        })
    }

    /// Returns the exact project identity that current policy must authorize.
    #[must_use]
    pub const fn project_id(&self) -> &RecordId {
        &self.project_id
    }

    /// Returns the canonical provider resource identity.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// HTTP mutation method supported by the fixed-endpoint adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// Idempotency-keyed resource creation or command submission.
    Post,
    /// Idempotency-keyed complete resource replacement.
    Put,
}

impl HttpMethod {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Post => b"POST",
            Self::Put => b"PUT",
        }
    }
}

/// Protected normalized request staged for a fixed HTTP endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct IdempotentHttpRequest {
    method: HttpMethod,
    content_type: String,
    body: Vec<u8>,
    resource_scope: HttpResourceScope,
}

impl IdempotentHttpRequest {
    /// Creates a bounded POST or PUT request body.
    pub fn new(
        _method: HttpMethod,
        _content_type: impl Into<String>,
        _body: Vec<u8>,
    ) -> Result<Self, EffectError> {
        // V1 opaque bodies could select an object that was absent from the authorization tuple.
        // Retain the source-compatible constructor only as a fail-closed migration boundary.
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    }

    /// Creates a bounded request whose body-selected object is explicit and policy-bindable.
    pub fn new_scoped(
        method: HttpMethod,
        content_type: impl Into<String>,
        body: Vec<u8>,
        resource_scope: HttpResourceScope,
    ) -> Result<Self, EffectError> {
        let request = Self {
            method,
            content_type: content_type.into(),
            body,
            resource_scope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the HTTP method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Returns the typed object selector bound into this request.
    #[must_use]
    pub const fn resource_scope(&self) -> &HttpResourceScope {
        &self.resource_scope
    }

    /// Computes the exact policy target for this endpoint and typed object selector.
    pub fn authorization_target(&self, endpoint: &str) -> Result<String, EffectError> {
        validate_https_endpoint(endpoint)?;
        let digest = digest_parts(
            b"idempotent-http-authorization-target",
            &[
                endpoint.as_bytes(),
                self.resource_scope.project_id.as_str().as_bytes(),
                self.resource_scope.resource_id.as_bytes(),
            ],
        )?;
        Ok(format!("cigar:http-resource:{}", digest.as_str()))
    }

    /// Computes the exact normalized argument digest.
    pub fn arguments_digest(&self) -> Result<ContentDigest, EffectError> {
        digest_parts(
            b"idempotent-http-request",
            &[
                self.method.as_bytes(),
                self.content_type.as_bytes(),
                &self.body,
                self.resource_scope.project_id.as_str().as_bytes(),
                self.resource_scope.resource_id.as_bytes(),
            ],
        )
    }

    /// Encodes a deterministic versioned JSON document suitable for encrypted blob storage.
    pub fn encode_protected_document(&self) -> Result<Vec<u8>, EffectError> {
        self.validate()?;
        let document = HttpArgumentDocument {
            schema_version: PROTECTED_ARGUMENT_SCHEMA.to_owned(),
            method: match self.method {
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
            }
            .to_owned(),
            content_type: self.content_type.clone(),
            body_base64url: URL_SAFE_NO_PAD.encode(&self.body),
            project_id: self.resource_scope.project_id.as_str().to_owned(),
            resource_id: self.resource_scope.resource_id.clone(),
        };
        let bytes = serde_json::to_vec(&document)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        Ok(bytes)
    }

    /// Decodes a strict versioned JSON document recovered from authenticated encrypted storage.
    pub fn decode_protected_document(bytes: &[u8]) -> Result<Self, EffectError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        cigar_canon::parse_strict_json(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let document: HttpArgumentDocument = serde_json::from_slice(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        if document.schema_version != PROTECTED_ARGUMENT_SCHEMA {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let method = match document.method.as_str() {
            "post" => HttpMethod::Post,
            "put" => HttpMethod::Put,
            _ => return Err(EffectError::new(EffectErrorCode::InvalidInput)),
        };
        let body = URL_SAFE_NO_PAD
            .decode(document.body_base64url)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let scope = HttpResourceScope::new(
            RecordId::new(document.project_id)
                .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?,
            document.resource_id,
        )?;
        Self::new_scoped(method, document.content_type, body, scope)
    }

    fn validate(&self) -> Result<(), EffectError> {
        validate_bounded_text(&self.content_type, 256)?;
        if self.content_type.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'+' | b'-' | b'.' | b';' | b'='))
        }) {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        if self.body.len() > MAX_REFERENCE_BODY_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        Ok(())
    }
}

impl fmt::Debug for IdempotentHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotentHttpRequest")
            .field("method", &self.method)
            .field("content_type_bytes", &self.content_type.len())
            .field("body_bytes", &self.body.len())
            .field("project_id", &self.resource_scope.project_id)
            .field("resource_id_bytes", &self.resource_scope.resource_id.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed request passed only to the caller-injected HTTP transport.
pub struct HttpTransportRequest<'a> {
    endpoint: &'a str,
    pinned_addresses: &'a BTreeSet<IpAddr>,
    method: HttpMethod,
    content_type: &'a str,
    body: &'a [u8],
    idempotency_scope: &'a str,
    idempotency_key: &'a IdempotencyKey,
    arguments_digest: &'a ContentDigest,
    attempt_id: &'a RecordId,
    fencing_token: u64,
    request_digest: &'a ContentDigest,
    deadline: UtcTimestamp,
    project_id: &'a RecordId,
    resource_id: &'a str,
}

impl HttpTransportRequest<'_> {
    /// Returns the constructor-fixed HTTPS endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &str {
        self.endpoint
    }

    /// Returns the constructor-verified public addresses the transport must use directly.
    #[must_use]
    pub const fn pinned_addresses(&self) -> &BTreeSet<IpAddr> {
        self.pinned_addresses
    }

    /// Returns the exact project selected by the authorized request.
    #[must_use]
    pub const fn project_id(&self) -> &RecordId {
        self.project_id
    }

    /// Returns the exact provider resource selected by the authorized request.
    #[must_use]
    pub const fn resource_id(&self) -> &str {
        self.resource_id
    }

    /// Returns the HTTP mutation method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Returns the normalized content type.
    #[must_use]
    pub const fn content_type(&self) -> &str {
        self.content_type
    }

    /// Returns protected body bytes to the injected transport.
    #[must_use]
    pub const fn body(&self) -> &[u8] {
        self.body
    }

    /// Returns the normalized idempotency scope.
    #[must_use]
    pub const fn idempotency_scope(&self) -> &str {
        self.idempotency_scope
    }

    /// Returns the secret-safe idempotency key for the transport header.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        self.idempotency_key
    }

    /// Returns the exact staged arguments digest.
    #[must_use]
    pub const fn arguments_digest(&self) -> &ContentDigest {
        self.arguments_digest
    }

    /// Returns the durable dispatch-attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> &RecordId {
        self.attempt_id
    }

    /// Returns the active monotonic fencing token.
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the exact request digest committed before transport entry.
    #[must_use]
    pub const fn request_digest(&self) -> &ContentDigest {
        self.request_digest
    }

    /// Returns the hard dispatch deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcTimestamp {
        self.deadline
    }
}

impl fmt::Debug for HttpTransportRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransportRequest")
            .field("endpoint", &self.endpoint)
            .field("pinned_address_count", &self.pinned_addresses.len())
            .field("method", &self.method)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .field("arguments_digest", &self.arguments_digest)
            .field("attempt_id", &self.attempt_id)
            .field("fencing_token", &self.fencing_token)
            .field("request_digest", &self.request_digest)
            .field("deadline", &self.deadline)
            .field("project_id", &self.project_id)
            .field("resource_id_bytes", &self.resource_id.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed idempotency lookup passed to the injected HTTP transport.
pub struct HttpTransportQuery<'a> {
    endpoint: &'a str,
    pinned_addresses: &'a BTreeSet<IpAddr>,
    idempotency_scope: &'a str,
    idempotency_key: &'a IdempotencyKey,
    arguments_digest: &'a ContentDigest,
    attempt_id: &'a RecordId,
    deadline: UtcTimestamp,
    project_id: &'a RecordId,
    resource_id: &'a str,
}

impl HttpTransportQuery<'_> {
    /// Returns the constructor-fixed HTTPS endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &str {
        self.endpoint
    }

    /// Returns the pinned public address set used by the original transport request.
    #[must_use]
    pub const fn pinned_addresses(&self) -> &BTreeSet<IpAddr> {
        self.pinned_addresses
    }

    /// Returns the authorized project selector.
    #[must_use]
    pub const fn project_id(&self) -> &RecordId {
        self.project_id
    }

    /// Returns the authorized provider resource selector.
    #[must_use]
    pub const fn resource_id(&self) -> &str {
        self.resource_id
    }

    /// Returns the normalized idempotency scope.
    #[must_use]
    pub const fn idempotency_scope(&self) -> &str {
        self.idempotency_scope
    }

    /// Returns the secret-safe idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        self.idempotency_key
    }

    /// Returns the exact staged arguments digest.
    #[must_use]
    pub const fn arguments_digest(&self) -> &ContentDigest {
        self.arguments_digest
    }

    /// Returns the ambiguous attempt being reconciled.
    #[must_use]
    pub const fn attempt_id(&self) -> &RecordId {
        self.attempt_id
    }

    /// Returns the current reconciliation-call deadline.
    #[must_use]
    pub const fn deadline(&self) -> UtcTimestamp {
        self.deadline
    }
}

impl fmt::Debug for HttpTransportQuery<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransportQuery")
            .field("endpoint", &self.endpoint)
            .field("pinned_address_count", &self.pinned_addresses.len())
            .field("arguments_digest", &self.arguments_digest)
            .field("attempt_id", &self.attempt_id)
            .field("deadline", &self.deadline)
            .field("project_id", &self.project_id)
            .field("resource_id_bytes", &self.resource_id.len())
            .finish_non_exhaustive()
    }
}

/// Explicit result of one injected HTTP transport send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpTransportObservation {
    /// The server committed and verified one idempotency-keyed mutation.
    Succeeded {
        /// Stable server operation identifier.
        remote_operation_id: String,
        /// Normalized response digest.
        response_digest: ContentDigest,
        /// Independent verification digest.
        verification_digest: ContentDigest,
    },
    /// The server definitively rejected the request without mutation.
    Rejected(ContentDigest),
    /// The transport proved that no request bytes capable of committing were sent.
    RequestNotSent(ContentDigest),
    /// The request may have committed and requires lookup by idempotency key.
    Ambiguous {
        /// Current evidence digest.
        evidence_digest: ContentDigest,
        /// Remote operation identity when learned before response loss.
        remote_operation_id: Option<String>,
    },
}

/// Explicit result of one injected HTTP idempotency lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpLookupObservation {
    /// One matching mutation is confirmed successful.
    ConfirmedSuccess(ContentDigest),
    /// The server confirms definitive failure.
    ConfirmedFailure(ContentDigest),
    /// The server's authoritative key index proves no mutation occurred.
    ProvenNotExecuted(ContentDigest),
    /// Lookup cannot yet determine whether the mutation committed.
    Inconclusive(ContentDigest),
}

/// Borrowed provider-specific body/resource binding presented to an injected typed transport.
pub struct HttpResourceBindingRequest<'a> {
    endpoint: &'a str,
    method: HttpMethod,
    content_type: &'a str,
    body: &'a [u8],
    resource_scope: &'a HttpResourceScope,
}

impl HttpResourceBindingRequest<'_> {
    /// Returns the immutable configured provider endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &str {
        self.endpoint
    }

    /// Returns the mutation method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Returns the normalized body media type.
    #[must_use]
    pub const fn content_type(&self) -> &str {
        self.content_type
    }

    /// Returns the exact protected body that the typed transport must parse or constrain.
    #[must_use]
    pub const fn body(&self) -> &[u8] {
        self.body
    }

    /// Returns the scope that must match body semantics and credential reach.
    #[must_use]
    pub const fn resource_scope(&self) -> &HttpResourceScope {
        self.resource_scope
    }
}

/// Transport-supplied proof of the exact network and idempotency boundary it enforces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpTransportSecurity {
    endpoint: String,
    pinned_addresses: BTreeSet<IpAddr>,
    redirects_disabled: bool,
    atomic_same_key: bool,
    resource_scope_enforced: bool,
}

impl HttpTransportSecurity {
    /// Describes an exact endpoint whose DNS results are pinned for dispatch and whose remote
    /// key index atomically coalesces identical idempotency keys.
    pub fn new(
        endpoint: impl Into<String>,
        pinned_addresses: impl IntoIterator<Item = IpAddr>,
        redirects_disabled: bool,
        atomic_same_key: bool,
        resource_scope_enforced: bool,
    ) -> Result<Self, EffectError> {
        let endpoint = endpoint.into();
        validate_https_endpoint(&endpoint)?;
        let pinned_addresses = pinned_addresses.into_iter().collect::<BTreeSet<_>>();
        if pinned_addresses.is_empty()
            || pinned_addresses.len() > MAX_RESOLVED_TARGET_ADDRESSES
            || pinned_addresses
                .iter()
                .any(|address| !public_address(address))
            || !redirects_disabled
            || !atomic_same_key
            || !resource_scope_enforced
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        Ok(Self {
            endpoint,
            pinned_addresses,
            redirects_disabled,
            atomic_same_key,
            resource_scope_enforced,
        })
    }

    /// Returns the exact endpoint this evidence covers.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the bounded public address set the transport must connect to without re-resolution.
    #[must_use]
    pub const fn pinned_addresses(&self) -> &BTreeSet<IpAddr> {
        &self.pinned_addresses
    }
}

/// No-network transport boundary injected into the idempotent HTTP connector.
pub trait HttpTransport: Send + Sync {
    /// Returns explicit endpoint capability and pinned-target evidence.
    ///
    /// The default denies legacy transports until they provide the production proof.
    fn security(&self) -> Result<HttpTransportSecurity, EffectError> {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    }

    /// Parses or independently constrains provider-specific body semantics to the exact declared
    /// project/resource and proves the credential cannot act outside that scope.
    ///
    /// Generic opaque transports inherit the fail-closed default.
    fn validate_resource_binding(
        &self,
        _request: &HttpResourceBindingRequest<'_>,
    ) -> Result<(), EffectError> {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    }

    /// Sends one fixed-endpoint request with the exact idempotency key.
    fn send(
        &self,
        request: &HttpTransportRequest<'_>,
    ) -> Result<HttpTransportObservation, EffectError>;

    /// Looks up prior execution without sending the mutation again.
    fn lookup(&self, query: &HttpTransportQuery<'_>) -> Result<HttpLookupObservation, EffectError>;
}

/// Fixed-endpoint idempotent HTTP connector backed by an injected transport.
pub struct IdempotentHttpConnector {
    connector_name: String,
    endpoint: String,
    transport: Arc<dyn HttpTransport>,
    security: HttpTransportSecurity,
    requests: RwLock<BTreeMap<ContentDigest, IdempotentHttpRequest>>,
}

impl fmt::Debug for IdempotentHttpConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request_count = self.requests.read().map_or(0, |items| items.len());
        formatter
            .debug_struct("IdempotentHttpConnector")
            .field("connector_name", &self.connector_name)
            .field("endpoint", &self.endpoint)
            .field("request_count", &request_count)
            .finish_non_exhaustive()
    }
}

impl IdempotentHttpConnector {
    /// Creates a connector for one immutable HTTPS endpoint and injected transport.
    pub fn new(
        connector_name: impl Into<String>,
        endpoint: impl Into<String>,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, EffectError> {
        let connector_name = connector_name.into();
        let endpoint = endpoint.into();
        validate_selector(&connector_name)?;
        validate_https_endpoint(&endpoint)?;
        let security = transport.security()?;
        if security.endpoint != endpoint
            || !security.redirects_disabled
            || !security.atomic_same_key
            || !security.resource_scope_enforced
            || security.pinned_addresses.is_empty()
        {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        Ok(Self {
            connector_name,
            endpoint,
            transport,
            security,
            requests: RwLock::new(BTreeMap::new()),
        })
    }

    /// Stages protected HTTP arguments and returns their exact digest.
    pub fn stage_request(
        &self,
        request: IdempotentHttpRequest,
    ) -> Result<ContentDigest, EffectError> {
        request.validate()?;
        self.validate_resource_binding(&request)?;
        let digest = request.arguments_digest()?;
        let mut requests = self
            .requests
            .write()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if requests
            .get(&digest)
            .is_some_and(|existing| existing != &request)
        {
            return Err(EffectError::new(EffectErrorCode::IdempotencyCollision));
        }
        requests.insert(digest.clone(), request);
        Ok(digest)
    }

    fn request(&self, digest: &ContentDigest) -> Result<IdempotentHttpRequest, EffectError> {
        self.requests
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(digest)
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    fn validate_intent(
        &self,
        intent: &cigar_protocol::EffectIntent,
    ) -> Result<IdempotentHttpRequest, EffectError> {
        if intent.connector != self.connector_name
            || intent.operation != SEND
            || !intent.preconditions.is_empty()
        {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let request = self.request(&intent.arguments_digest)?;
        self.validate_resource_binding(&request)?;
        if intent.target != request.authorization_target(&self.endpoint)? {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        Ok(request)
    }

    fn validate_resource_binding(
        &self,
        request: &IdempotentHttpRequest,
    ) -> Result<(), EffectError> {
        self.transport
            .validate_resource_binding(&HttpResourceBindingRequest {
                endpoint: &self.endpoint,
                method: request.method,
                content_type: &request.content_type,
                body: &request.body,
                resource_scope: &request.resource_scope,
            })
    }

    fn query<'a>(
        &'a self,
        context: &'a DispatchContext<'a>,
        request: &'a IdempotentHttpRequest,
    ) -> HttpTransportQuery<'a> {
        HttpTransportQuery {
            endpoint: &self.endpoint,
            pinned_addresses: &self.security.pinned_addresses,
            idempotency_scope: &context.intent.idempotency_scope,
            idempotency_key: &context.intent.idempotency_key,
            arguments_digest: &context.intent.arguments_digest,
            attempt_id: context.attempt_id,
            deadline: context.deadline,
            project_id: &request.resource_scope.project_id,
            resource_id: &request.resource_scope.resource_id,
        }
    }
}

impl EffectConnector for IdempotentHttpConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: self.connector_name.clone(),
            operations: vec![ConnectorOperation {
                operation: SEND.to_owned(),
                same_key_idempotent: true,
                supports_reconciliation: true,
                supports_compensation: false,
            }],
            maximum_dispatch_nanos: 30_000_000_000,
        }
    }

    fn check_preconditions(
        &self,
        intent: &cigar_protocol::EffectIntent,
        _now: cigar_protocol::UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        let valid = self.validate_intent(intent).is_ok();
        Ok(PreconditionReport {
            satisfied: valid,
            evidence: BTreeSet::from([stable_evidence(b"http-fixed-endpoint", intent)?]),
        })
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        let transport_request = HttpTransportRequest {
            endpoint: &self.endpoint,
            pinned_addresses: &self.security.pinned_addresses,
            method: request.method,
            content_type: &request.content_type,
            body: &request.body,
            idempotency_scope: &context.intent.idempotency_scope,
            idempotency_key: &context.intent.idempotency_key,
            arguments_digest: &context.intent.arguments_digest,
            attempt_id: context.attempt_id,
            fencing_token: context.fencing_token,
            request_digest: context.request_digest,
            deadline: context.deadline,
            project_id: &request.resource_scope.project_id,
            resource_id: &request.resource_scope.resource_id,
        };
        match self.transport.send(&transport_request)? {
            HttpTransportObservation::Succeeded {
                remote_operation_id,
                response_digest,
                verification_digest,
            } => Ok(DispatchObservation::Succeeded {
                remote_operation_id,
                response_digest,
                verification_digest,
            }),
            HttpTransportObservation::Rejected(evidence_digest) => {
                Ok(DispatchObservation::Failed { evidence_digest })
            }
            HttpTransportObservation::RequestNotSent(evidence_digest) => {
                Ok(DispatchObservation::ProvenNotSent { evidence_digest })
            }
            HttpTransportObservation::Ambiguous {
                evidence_digest,
                remote_operation_id,
            } => Ok(DispatchObservation::Unknown {
                evidence_digest,
                remote_operation_id,
            }),
        }
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        match self.transport.lookup(&self.query(context, &request))? {
            HttpLookupObservation::ConfirmedSuccess(evidence) => {
                Ok(ReconcileObservation::ConfirmedSuccess(evidence))
            }
            HttpLookupObservation::ConfirmedFailure(evidence) => {
                Ok(ReconcileObservation::ConfirmedFailure(evidence))
            }
            HttpLookupObservation::ProvenNotExecuted(evidence) => {
                Ok(ReconcileObservation::ProvenNotExecuted(evidence))
            }
            HttpLookupObservation::Inconclusive(evidence_digest) => {
                Ok(ReconcileObservation::Inconclusive {
                    evidence_digest,
                    certainty_window_end: context.deadline,
                })
            }
        }
    }
}

fn validate_https_endpoint(endpoint: &str) -> Result<(), EffectError> {
    let Some(authority_and_path) = endpoint.strip_prefix("https://") else {
        return Err(EffectError::new(EffectErrorCode::InvalidInput));
    };
    let (authority, path) = authority_and_path
        .split_once('/')
        .map_or((authority_and_path, ""), |(value, path)| (value, path));
    if endpoint.len() > 256
        || !endpoint.is_ascii()
        || authority.is_empty()
        || authority.contains('@')
        || endpoint.contains(['?', '#', '\\', '%'])
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || authority.bytes().any(|byte| byte.is_ascii_uppercase())
        || !valid_authority(authority)
        || !valid_normalized_path(path)
    {
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn valid_authority(authority: &str) -> bool {
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    let port_valid = port.is_none_or(|value| {
        !value.is_empty()
            && !value.starts_with('0')
            && value
                .parse::<u16>()
                .is_ok_and(|parsed| parsed != 0 && parsed != 443)
    });
    port_valid
        && host.parse::<IpAddr>().is_err()
        && !matches!(host, "localhost" | "localhost.localdomain")
        && !host.ends_with(".localhost")
        && !host.ends_with(".local")
        && !host.ends_with(".internal")
        && !host.ends_with(".home.arpa")
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn public_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _d] = address.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || a == 100 && (64..=127).contains(&b)
                || a == 169 && b == 254
                || a == 172 && (16..=31).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 0 && c == 2
                || a == 192 && b == 88 && c == 99
                || a == 192 && b == 168
                || a == 198 && (b == 18 || b == 19)
                || a == 198 && b == 51 && c == 100
                || a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(address) => {
            let [network, subnet, ..] = address.segments();
            network & 0xe000 == 0x2000
                && !(network == 0x2001 && subnet <= 0x01ff)
                && !(network == 0x2001 && subnet == 0x0db8)
                && network != 0x2002
                && !(network == 0x3fff && subnet & 0xf000 == 0)
        }
    }
}

fn valid_normalized_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let mut segments = path.split('/').peekable();
    while let Some(segment) = segments.next() {
        let trailing_empty = segment.is_empty() && segments.peek().is_none();
        if (!trailing_empty && (segment.is_empty() || matches!(segment, "." | "..")))
            || segment.bytes().any(|byte| {
                !(byte.is_ascii_lowercase()
                    || byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b'~'))
            })
        {
            return false;
        }
    }
    true
}
