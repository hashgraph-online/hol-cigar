//! Disabled-by-default macOS HTTPS transport boundary for production effect connectors.
//!
//! The stock transport deliberately implements one small provider-neutral wire contract. It
//! resolves one immutable HTTPS endpoint once, rejects every non-public answer, installs those
//! addresses as direct resolver overrides while retaining the configured hostname for TLS identity,
//! and disables redirects, proxies, retries, referrers, and content decoding. An owner-private
//! credential document binds one opaque handle to the exact origin and project/resource scope. The
//! credential is re-read at each dispatch and lookup so rotation and expiry fail closed.

use crate::process::read_secret_bytes;
use crate::{
    EffectDispatchGate, ProductionEffectRegistryError, ProductionHttpTransportFactory,
    ProductionHttpsEffectTransportConfiguration,
};
use cigar_canon::parse_strict_json;
use cigar_effects::reference::{
    HttpLookupObservation, HttpMethod, HttpResourceBindingRequest, HttpTransport,
    HttpTransportObservation, HttpTransportQuery, HttpTransportRequest, HttpTransportSecurity,
};
use cigar_effects::{EffectError, EffectErrorCode};
use cigar_protocol::{ContentDigest, RecordId};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue,
};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize as _, Zeroizing};

/// Exact request-body media type understood by the provider-neutral stock transport.
pub const SCOPED_EFFECT_BODY_MEDIA_TYPE: &str = "application/vnd.cigar.scoped-effect-request+json";
/// Exact bounded response media type understood by the stock transport.
pub const EFFECT_RESULT_MEDIA_TYPE: &str = "application/vnd.cigar.effect-result+json";
/// Exact provider protocol whose same-key atomicity and lookup semantics the stock adapter uses.
pub const STOCK_HTTPS_EFFECT_PROTOCOL: &str = "cigar.idempotent-effect-http.v1";

const CREDENTIAL_SCHEMA: &str = "cigar.scoped-http-credential.v1";
const SCOPED_BODY_SCHEMA: &str = "cigar.scoped-effect-request.v1";
const RESULT_SCHEMA: &str = "cigar.idempotent-effect-result.v1";
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1_024;
const MAX_CREDENTIAL_HANDLE_BYTES: usize = 256;
const MIN_BEARER_TOKEN_BYTES: usize = 16;
const MAX_BEARER_TOKEN_BYTES: usize = 8 * 1_024;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_REMOTE_OPERATION_BYTES: usize = 512;
const MAX_CONNECT_TIMEOUT_MS: u64 = 10_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 30_000;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(2);

const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const CIGAR_OPERATION: HeaderName = HeaderName::from_static("x-cigar-operation");
const CIGAR_IDEMPOTENCY_SCOPE: HeaderName = HeaderName::from_static("x-cigar-idempotency-scope");
const CIGAR_ARGUMENTS_DIGEST: HeaderName = HeaderName::from_static("x-cigar-arguments-digest");
const CIGAR_ATTEMPT_ID: HeaderName = HeaderName::from_static("x-cigar-attempt-id");
const CIGAR_FENCING_TOKEN: HeaderName = HeaderName::from_static("x-cigar-fencing-token");
const CIGAR_REQUEST_DIGEST: HeaderName = HeaderName::from_static("x-cigar-request-digest");
const CIGAR_REQUEST_BINDING: HeaderName = HeaderName::from_static("x-cigar-request-binding");

impl ProductionHttpsEffectTransportConfiguration {
    /// Validates strict bounds and the non-secret credential handle/path without reading secrets.
    pub fn validate_for_endpoint(
        &self,
        endpoint: &str,
    ) -> Result<(), ProductionHttpsEffectTransportError> {
        parse_endpoint(endpoint)?;
        if self.provider_protocol != STOCK_HTTPS_EFFECT_PROTOCOL
            || !valid_selector(&self.credential_handle)
            || !self.credential_file.is_absolute()
            || self.pinned_addresses.is_empty()
            || self.pinned_addresses.len() > MAX_RESOLVED_ADDRESSES
            || self
                .pinned_addresses
                .windows(2)
                .any(|addresses| !matches!(addresses, [first, second] if first < second))
            || !(1..=MAX_CONNECT_TIMEOUT_MS).contains(&self.connect_timeout_ms)
            || !(1..=MAX_REQUEST_TIMEOUT_MS).contains(&self.request_timeout_ms)
            || self.connect_timeout_ms > self.request_timeout_ms
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.maximum_response_bytes)
        {
            return Err(ProductionHttpsEffectTransportError::InvalidConfiguration);
        }
        HttpTransportSecurity::new(
            endpoint,
            self.pinned_addresses.iter().copied(),
            true,
            true,
            true,
        )
        .map_err(|_error| ProductionHttpsEffectTransportError::InvalidConfiguration)?;
        Ok(())
    }

    const fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

/// Content-free construction failure for the stock HTTPS transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionHttpsEffectTransportError {
    /// Endpoint, bounds, credential handle, or credential file configuration was invalid.
    InvalidConfiguration,
    /// The endpoint's explicit bounded public address pins were unavailable or inconsistent.
    ResolutionUnavailable,
    /// The TLS client could not be constructed.
    TransportUnavailable,
    /// The owner-private credential document was absent, unsafe, malformed, expired, or unscoped.
    CredentialUnavailable,
}

impl fmt::Display for ProductionHttpsEffectTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production HTTPS effect transport is unavailable")
    }
}

impl std::error::Error for ProductionHttpsEffectTransportError {}

#[derive(Clone)]
struct ParsedEndpoint {
    url: Url,
    origin: String,
    host: String,
    port: u16,
}

fn parse_endpoint(endpoint: &str) -> Result<ParsedEndpoint, ProductionHttpsEffectTransportError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || !endpoint.is_ascii()
        || endpoint.contains(['\\', '%'])
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ProductionHttpsEffectTransportError::InvalidConfiguration);
    }
    let url = Url::parse(endpoint)
        .map_err(|_error| ProductionHttpsEffectTransportError::InvalidConfiguration)?;
    let host = url
        .host_str()
        .ok_or(ProductionHttpsEffectTransportError::InvalidConfiguration)?;
    let canonical = url.as_str();
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || canonical != endpoint
        || host.parse::<IpAddr>().is_ok()
        || !valid_dns_name(host)
        || !valid_endpoint_path(url.path())
    {
        return Err(ProductionHttpsEffectTransportError::InvalidConfiguration);
    }
    let port = url
        .port_or_known_default()
        .ok_or(ProductionHttpsEffectTransportError::InvalidConfiguration)?;
    Ok(ParsedEndpoint {
        origin: url.origin().ascii_serialization(),
        host: host.to_owned(),
        port,
        url,
    })
}

fn valid_dns_name(host: &str) -> bool {
    host.contains('.')
        && !matches!(host, "localhost" | "localhost.localdomain")
        && !host.ends_with(".localhost")
        && !host.ends_with(".local")
        && !host.ends_with(".internal")
        && !host.ends_with(".home.arpa")
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

fn valid_endpoint_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let Some(path) = path.strip_prefix('/') else {
        return false;
    };
    path.split('/').all(|segment| {
        !segment.is_empty()
            && !matches!(segment, "." | "..")
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    })
}

fn valid_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_HANDLE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedCredentialDocument {
    schema_version: String,
    handle: String,
    endpoint_origin: String,
    project_id: RecordId,
    resource_id: String,
    not_before_unix_nanos: i128,
    expires_at_unix_nanos: i128,
    bearer_token: String,
}

impl Drop for ScopedCredentialDocument {
    fn drop(&mut self) {
        self.bearer_token.zeroize();
    }
}

struct ScopedCredential {
    token: Zeroizing<Vec<u8>>,
}

impl ScopedCredential {
    fn authorization_header(&self) -> Result<HeaderValue, EffectError> {
        let mut encoded = Zeroizing::new(Vec::with_capacity(self.token.len().saturating_add(7)));
        encoded.extend_from_slice(b"Bearer ");
        encoded.extend_from_slice(&self.token);
        let mut header = HeaderValue::from_bytes(&encoded)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unauthorized))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedEffectBody {
    schema_version: String,
    project_id: RecordId,
    resource_id: String,
    payload: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireOutcome {
    Succeeded,
    Rejected,
    Ambiguous,
    ConfirmedSuccess,
    ConfirmedFailure,
    ProvenNotExecuted,
    Inconclusive,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireResult {
    schema_version: String,
    request_binding: ContentDigest,
    outcome: WireOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_digest: Option<ContentDigest>,
}

impl WireResult {
    fn valid_remote_operation(&self) -> bool {
        self.remote_operation_id.as_ref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= MAX_REMOTE_OPERATION_BYTES
                && !value.bytes().any(|byte| byte.is_ascii_control())
        })
    }
}

fn valid_bearer_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(MIN_BEARER_TOKEN_BYTES..=MAX_BEARER_TOKEN_BYTES).contains(&bytes.len()) {
        return false;
    }
    let mut padding = false;
    bytes.iter().copied().all(|byte| {
        if byte == b'=' {
            padding = true;
            true
        } else {
            !padding
                && (byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
        }
    })
}

fn unix_now_nanos() -> Result<i128, EffectError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
    i128::try_from(duration.as_nanos())
        .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<ContentDigest, EffectError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PRODUCTION-HTTPS-EFFECT\0v1\0");
    update_digest_part(&mut hasher, domain)?;
    for part in parts {
        update_digest_part(&mut hasher, part)?;
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))
}

fn update_digest_part(hasher: &mut Sha256, value: &[u8]) -> Result<(), EffectError> {
    let length = u64::try_from(value.len())
        .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

struct OutboundRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    timeout: Duration,
    maximum_response_bytes: usize,
}

impl fmt::Debug for OutboundRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRequest")
            .field("method", &self.method)
            .field("origin", &self.url.origin().ascii_serialization())
            .field("header_count", &self.headers.len())
            .field(
                "body_bytes",
                &self.body.as_ref().map_or(0, std::vec::Vec::len),
            )
            .field("timeout", &self.timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .finish_non_exhaustive()
    }
}

struct OutboundResponse {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionFailure {
    DefinitelyNotSent,
    Ambiguous,
}

type ExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OutboundResponse, ExecutionFailure>> + Send + 'a>>;

trait HttpsExecutor: Send + Sync {
    fn execute(&self, request: OutboundRequest) -> ExecutionFuture<'_>;
}

struct ReqwestHttpsExecutor {
    client: reqwest::Client,
}

impl ReqwestHttpsExecutor {
    fn new(
        endpoint: &ParsedEndpoint,
        addresses: &[SocketAddr],
        connect_timeout: Duration,
    ) -> Result<Self, ProductionHttpsEffectTransportError> {
        let _provider_result = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .referer(false)
            .retry(reqwest::retry::never())
            .connect_timeout(connect_timeout)
            .pool_max_idle_per_host(0)
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(&endpoint.host, addresses)
            .build()
            .map_err(|_error| ProductionHttpsEffectTransportError::TransportUnavailable)?;
        Ok(Self { client })
    }

    #[cfg(test)]
    fn new_with_test_roots(
        endpoint: &ParsedEndpoint,
        addresses: &[SocketAddr],
        connect_timeout: Duration,
        roots: &[Vec<u8>],
    ) -> Result<Self, ProductionHttpsEffectTransportError> {
        let _provider_result = rustls::crypto::ring::default_provider().install_default();
        let roots = roots
            .iter()
            .map(|root| reqwest::tls::Certificate::from_der(root))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| ProductionHttpsEffectTransportError::TransportUnavailable)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .referer(false)
            .retry(reqwest::retry::never())
            .connect_timeout(connect_timeout)
            .pool_max_idle_per_host(0)
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(&endpoint.host, addresses)
            .tls_certs_only(roots)
            .build()
            .map_err(|_error| ProductionHttpsEffectTransportError::TransportUnavailable)?;
        Ok(Self { client })
    }
}

impl fmt::Debug for ReqwestHttpsExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReqwestHttpsExecutor")
            .field("client", &"[PINNED HTTPS; NO PROXY; NO REDIRECT]")
            .finish()
    }
}

impl HttpsExecutor for ReqwestHttpsExecutor {
    fn execute(&self, request: OutboundRequest) -> ExecutionFuture<'_> {
        Box::pin(async move {
            let OutboundRequest {
                method,
                url,
                headers,
                body,
                timeout,
                maximum_response_bytes,
            } = request;
            let mut builder = self
                .client
                .request(method, url)
                .headers(headers)
                .timeout(timeout);
            if let Some(body) = body {
                builder = builder.body(body);
            }
            let mut response = builder.send().await.map_err(map_reqwest_error)?;
            if response.content_length().is_some_and(|length| {
                usize::try_from(length).map_or(true, |length| length > maximum_response_bytes)
            }) {
                return Err(ExecutionFailure::Ambiguous);
            }
            let status = response.status();
            let content_type = response.headers().get(CONTENT_TYPE).cloned();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
                let next = bytes
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(ExecutionFailure::Ambiguous)?;
                if next > maximum_response_bytes {
                    return Err(ExecutionFailure::Ambiguous);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(OutboundResponse {
                status,
                content_type,
                body: bytes,
            })
        })
    }
}

fn map_reqwest_error(error: reqwest::Error) -> ExecutionFailure {
    if error.is_connect() || error.is_builder() {
        ExecutionFailure::DefinitelyNotSent
    } else {
        ExecutionFailure::Ambiguous
    }
}

/// Factory for one stock transport per configured HTTPS effect connector.
pub struct StockHttpsEffectTransportFactory {
    runtime: tokio::runtime::Handle,
    dispatch_gate: Arc<dyn EffectDispatchGate>,
}

impl StockHttpsEffectTransportFactory {
    /// Captures the existing async runtime and the daemon shutdown/dispatch gate.
    #[must_use]
    pub fn new(
        runtime: tokio::runtime::Handle,
        dispatch_gate: Arc<dyn EffectDispatchGate>,
    ) -> Self {
        Self {
            runtime,
            dispatch_gate,
        }
    }

    /// Builds a fresh fixed-origin, DNS-pinned transport for one connector.
    pub fn build(
        &self,
        endpoint: &str,
        configuration: ProductionHttpsEffectTransportConfiguration,
    ) -> Result<Arc<dyn HttpTransport>, ProductionHttpsEffectTransportError> {
        configuration.validate_for_endpoint(endpoint)?;
        let parsed = parse_endpoint(endpoint)?;
        let addresses = configuration
            .pinned_addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, parsed.port))
            .collect();
        let transport = StockHttpsEffectTransport::new_with_dependencies(
            endpoint,
            configuration,
            self.runtime.clone(),
            Arc::clone(&self.dispatch_gate),
            addresses,
            None,
        )?;
        Ok(Arc::new(transport))
    }
}

impl fmt::Debug for StockHttpsEffectTransportFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StockHttpsEffectTransportFactory")
            .field("runtime", &"[EXISTING]")
            .field("dispatch_gate", &"[INJECTED]")
            .finish()
    }
}

impl ProductionHttpTransportFactory for StockHttpsEffectTransportFactory {
    fn build(
        &self,
        endpoint: &str,
        configuration: ProductionHttpsEffectTransportConfiguration,
    ) -> Result<Arc<dyn HttpTransport>, ProductionEffectRegistryError> {
        StockHttpsEffectTransportFactory::build(self, endpoint, configuration)
            .map_err(|_error| ProductionEffectRegistryError::ConnectorUnavailable)
    }
}

struct StockHttpsEffectTransport {
    endpoint: ParsedEndpoint,
    configuration: ProductionHttpsEffectTransportConfiguration,
    runtime: tokio::runtime::Handle,
    dispatch_gate: Arc<dyn EffectDispatchGate>,
    executor: Arc<dyn HttpsExecutor>,
    security: HttpTransportSecurity,
}

impl StockHttpsEffectTransport {
    fn new_with_dependencies(
        endpoint: &str,
        configuration: ProductionHttpsEffectTransportConfiguration,
        runtime: tokio::runtime::Handle,
        dispatch_gate: Arc<dyn EffectDispatchGate>,
        addresses: Vec<SocketAddr>,
        executor: Option<Arc<dyn HttpsExecutor>>,
    ) -> Result<Self, ProductionHttpsEffectTransportError> {
        configuration.validate_for_endpoint(endpoint)?;
        let parsed = parse_endpoint(endpoint)?;
        if addresses.is_empty()
            || addresses.len() > MAX_RESOLVED_ADDRESSES
            || addresses
                .iter()
                .any(|address| address.port() != parsed.port)
        {
            return Err(ProductionHttpsEffectTransportError::ResolutionUnavailable);
        }
        let socket_addresses = addresses.into_iter().collect::<BTreeSet<_>>();
        if socket_addresses.is_empty() || socket_addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(ProductionHttpsEffectTransportError::ResolutionUnavailable);
        }
        let pinned_addresses = socket_addresses
            .iter()
            .map(SocketAddr::ip)
            .collect::<BTreeSet<_>>();
        let configured_addresses = configuration
            .pinned_addresses
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if pinned_addresses != configured_addresses {
            return Err(ProductionHttpsEffectTransportError::ResolutionUnavailable);
        }
        let security = HttpTransportSecurity::new(endpoint, pinned_addresses, true, true, true)
            .map_err(|_error| ProductionHttpsEffectTransportError::ResolutionUnavailable)?;
        let socket_addresses = socket_addresses.into_iter().collect::<Vec<_>>();
        let executor = match executor {
            Some(executor) => executor,
            None => Arc::new(ReqwestHttpsExecutor::new(
                &parsed,
                &socket_addresses,
                configuration.connect_timeout(),
            )?),
        };
        let transport = Self {
            endpoint: parsed,
            configuration,
            runtime,
            dispatch_gate,
            executor,
            security,
        };
        // Startup proves the configured secret file is readable and exactly binds the handle and
        // origin. Scope and lifetime are rechecked against each request below.
        transport.load_credential(None, None)?;
        Ok(transport)
    }

    fn load_credential(
        &self,
        expected_project: Option<&RecordId>,
        expected_resource: Option<&str>,
    ) -> Result<ScopedCredential, ProductionHttpsEffectTransportError> {
        let bytes = Zeroizing::new(
            read_secret_bytes(&self.configuration.credential_file, MAX_CREDENTIAL_BYTES)
                .map_err(|_error| ProductionHttpsEffectTransportError::CredentialUnavailable)?,
        );
        parse_strict_json(&bytes)
            .map_err(|_error| ProductionHttpsEffectTransportError::CredentialUnavailable)?;
        let mut document: ScopedCredentialDocument = serde_json::from_slice(&bytes)
            .map_err(|_error| ProductionHttpsEffectTransportError::CredentialUnavailable)?;
        let now = unix_now_nanos()
            .map_err(|_error| ProductionHttpsEffectTransportError::CredentialUnavailable)?;
        if document.schema_version != CREDENTIAL_SCHEMA
            || document.handle != self.configuration.credential_handle
            || document.endpoint_origin != self.endpoint.origin
            || !valid_selector(&document.handle)
            || !valid_resource_id(&document.resource_id)
            || document.expires_at_unix_nanos <= document.not_before_unix_nanos
            || now < document.not_before_unix_nanos
            || now >= document.expires_at_unix_nanos
            || !valid_bearer_token(&document.bearer_token)
            || expected_project.is_some_and(|project| project != &document.project_id)
            || expected_resource.is_some_and(|resource| resource != document.resource_id)
        {
            return Err(ProductionHttpsEffectTransportError::CredentialUnavailable);
        }
        Ok(ScopedCredential {
            token: Zeroizing::new(std::mem::take(&mut document.bearer_token).into_bytes()),
        })
    }

    fn validate_scoped_body(
        &self,
        request: &HttpResourceBindingRequest<'_>,
    ) -> Result<(), EffectError> {
        if request.endpoint() != self.endpoint.url.as_str() {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        validate_scoped_document(
            request.content_type(),
            request.body(),
            request.resource_scope().project_id(),
            request.resource_scope().resource_id(),
        )?;
        self.load_credential(
            Some(request.resource_scope().project_id()),
            Some(request.resource_scope().resource_id()),
        )
        .map(|_credential| ())
        .map_err(|_error| EffectError::new(EffectErrorCode::Unauthorized))
    }

    fn validate_transport_boundary(
        &self,
        endpoint: &str,
        pinned_addresses: &BTreeSet<IpAddr>,
    ) -> Result<(), EffectError> {
        if endpoint != self.endpoint.url.as_str()
            || pinned_addresses != self.security.pinned_addresses()
        {
            Err(EffectError::new(EffectErrorCode::Unauthorized))
        } else {
            Ok(())
        }
    }

    fn remaining_timeout(&self, deadline_unix_nanos: i128) -> Result<Duration, ExecutionFailure> {
        let now = unix_now_nanos().map_err(|_error| ExecutionFailure::DefinitelyNotSent)?;
        let remaining = deadline_unix_nanos
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or(ExecutionFailure::DefinitelyNotSent)?;
        let remaining = u64::try_from(remaining).unwrap_or(u64::MAX);
        Ok(Duration::from_nanos(remaining).min(self.configuration.request_timeout()))
    }

    fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, ExecutionFailure> {
        if !self.dispatch_gate.dispatch_claims_allowed() {
            return Err(ExecutionFailure::DefinitelyNotSent);
        }
        let timeout = request.timeout;
        let execution = self.executor.execute(request);
        let gate = Arc::clone(&self.dispatch_gate);
        let future = async move {
            let mut timeout_sleep = Box::pin(tokio::time::sleep(timeout));
            let mut execution = execution;
            loop {
                tokio::select! {
                    response = &mut execution => return response,
                    () = &mut timeout_sleep => return Err(ExecutionFailure::Ambiguous),
                    () = tokio::time::sleep(CANCELLATION_POLL_INTERVAL) => {
                        if !gate.dispatch_claims_allowed() {
                            return Err(ExecutionFailure::Ambiguous);
                        }
                    }
                }
            }
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.runtime.block_on(future)
        }))
        .unwrap_or(Err(ExecutionFailure::Ambiguous))
    }
}

impl fmt::Debug for StockHttpsEffectTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StockHttpsEffectTransport")
            .field("origin", &self.endpoint.origin)
            .field("credential", &"[SCOPED OWNER-PRIVATE HANDLE]")
            .field(
                "pinned_address_count",
                &self.security.pinned_addresses().len(),
            )
            .field("request_timeout", &self.configuration.request_timeout())
            .field(
                "maximum_response_bytes",
                &self.configuration.maximum_response_bytes,
            )
            .finish_non_exhaustive()
    }
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
}

fn validate_scoped_document(
    content_type: &str,
    bytes: &[u8],
    project_id: &RecordId,
    resource_id: &str,
) -> Result<(), EffectError> {
    if content_type != SCOPED_EFFECT_BODY_MEDIA_TYPE {
        return Err(EffectError::new(EffectErrorCode::Unauthorized));
    }
    parse_strict_json(bytes).map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    let body: ScopedEffectBody = serde_json::from_slice(bytes)
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    let _payload = &body.payload;
    if body.schema_version != SCOPED_BODY_SCHEMA
        || &body.project_id != project_id
        || body.resource_id != resource_id
        || !valid_resource_id(&body.resource_id)
    {
        return Err(EffectError::new(EffectErrorCode::Unauthorized));
    }
    Ok(())
}

fn header_value(value: &str) -> Result<HeaderValue, EffectError> {
    HeaderValue::from_str(value).map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))
}

fn send_binding(request: &HttpTransportRequest<'_>) -> Result<ContentDigest, EffectError> {
    digest_parts(
        b"dispatch-request-binding",
        &[
            request.endpoint().as_bytes(),
            request.project_id().as_str().as_bytes(),
            request.resource_id().as_bytes(),
            request.idempotency_scope().as_bytes(),
            request.idempotency_key().as_str().as_bytes(),
            request.arguments_digest().as_str().as_bytes(),
            request.attempt_id().as_str().as_bytes(),
            &request.fencing_token().to_be_bytes(),
            request.request_digest().as_str().as_bytes(),
        ],
    )
}

fn lookup_binding(query: &HttpTransportQuery<'_>) -> Result<ContentDigest, EffectError> {
    digest_parts(
        b"lookup-request-binding",
        &[
            query.endpoint().as_bytes(),
            query.project_id().as_str().as_bytes(),
            query.resource_id().as_bytes(),
            query.idempotency_scope().as_bytes(),
            query.idempotency_key().as_str().as_bytes(),
            query.arguments_digest().as_str().as_bytes(),
            query.attempt_id().as_str().as_bytes(),
        ],
    )
}

fn evidence(domain: &[u8], binding: &ContentDigest) -> Result<ContentDigest, EffectError> {
    digest_parts(domain, &[binding.as_str().as_bytes()])
}

fn common_headers(
    credential: &ScopedCredential,
    operation: &'static str,
    idempotency_scope: &str,
    idempotency_key: &str,
    arguments_digest: &ContentDigest,
    attempt_id: &RecordId,
    binding: &ContentDigest,
) -> Result<HeaderMap, EffectError> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(EFFECT_RESULT_MEDIA_TYPE));
    headers.insert(AUTHORIZATION, credential.authorization_header()?);
    headers.insert(CIGAR_OPERATION, HeaderValue::from_static(operation));
    headers.insert(IDEMPOTENCY_KEY, header_value(idempotency_key)?);
    headers.insert(CIGAR_IDEMPOTENCY_SCOPE, header_value(idempotency_scope)?);
    headers.insert(
        CIGAR_ARGUMENTS_DIGEST,
        header_value(arguments_digest.as_str())?,
    );
    headers.insert(CIGAR_ATTEMPT_ID, header_value(attempt_id.as_str())?);
    headers.insert(CIGAR_REQUEST_BINDING, header_value(binding.as_str())?);
    Ok(headers)
}

fn parse_wire_result(
    response: OutboundResponse,
    binding: &ContentDigest,
) -> Result<WireResult, ()> {
    if response.status != StatusCode::OK
        || response
            .content_type
            .as_ref()
            .and_then(|value| value.to_str().ok())
            != Some(EFFECT_RESULT_MEDIA_TYPE)
        || response.body.is_empty()
        || parse_strict_json(&response.body).is_err()
    {
        return Err(());
    }
    let result: WireResult = serde_json::from_slice(&response.body).map_err(|_error| ())?;
    if result.schema_version != RESULT_SCHEMA
        || &result.request_binding != binding
        || !result.valid_remote_operation()
    {
        return Err(());
    }
    Ok(result)
}

fn map_send_result(
    response: OutboundResponse,
    binding: &ContentDigest,
) -> Result<HttpTransportObservation, EffectError> {
    let invalid = || {
        evidence(b"invalid-dispatch-response", binding).map(|evidence_digest| {
            HttpTransportObservation::Ambiguous {
                evidence_digest,
                remote_operation_id: None,
            }
        })
    };
    let result = match parse_wire_result(response, binding) {
        Ok(result) => result,
        Err(()) => return invalid(),
    };
    match result.outcome {
        WireOutcome::Succeeded => match (
            result.remote_operation_id,
            result.response_digest,
            result.verification_digest,
            result.evidence_digest,
        ) {
            (Some(remote_operation_id), Some(response_digest), Some(verification_digest), None) => {
                Ok(HttpTransportObservation::Succeeded {
                    remote_operation_id,
                    response_digest,
                    verification_digest,
                })
            }
            _ => invalid(),
        },
        WireOutcome::Rejected => match (
            result.remote_operation_id,
            result.response_digest,
            result.verification_digest,
            result.evidence_digest,
        ) {
            (None, None, None, Some(evidence_digest)) => {
                Ok(HttpTransportObservation::Rejected(evidence_digest))
            }
            _ => invalid(),
        },
        WireOutcome::Ambiguous => match (
            result.remote_operation_id,
            result.response_digest,
            result.verification_digest,
            result.evidence_digest,
        ) {
            (remote_operation_id, None, None, Some(evidence_digest)) => {
                Ok(HttpTransportObservation::Ambiguous {
                    evidence_digest,
                    remote_operation_id,
                })
            }
            _ => invalid(),
        },
        WireOutcome::ConfirmedSuccess
        | WireOutcome::ConfirmedFailure
        | WireOutcome::ProvenNotExecuted
        | WireOutcome::Inconclusive => invalid(),
    }
}

fn map_lookup_result(
    response: OutboundResponse,
    binding: &ContentDigest,
) -> Result<HttpLookupObservation, EffectError> {
    let invalid =
        || evidence(b"invalid-lookup-response", binding).map(HttpLookupObservation::Inconclusive);
    let result = match parse_wire_result(response, binding) {
        Ok(result) => result,
        Err(()) => return invalid(),
    };
    let evidence_digest = match (
        result.remote_operation_id,
        result.response_digest,
        result.verification_digest,
        result.evidence_digest,
    ) {
        (None, None, None, Some(evidence_digest)) => evidence_digest,
        _ => return invalid(),
    };
    match result.outcome {
        WireOutcome::ConfirmedSuccess => {
            Ok(HttpLookupObservation::ConfirmedSuccess(evidence_digest))
        }
        WireOutcome::ConfirmedFailure => {
            Ok(HttpLookupObservation::ConfirmedFailure(evidence_digest))
        }
        WireOutcome::ProvenNotExecuted => {
            Ok(HttpLookupObservation::ProvenNotExecuted(evidence_digest))
        }
        WireOutcome::Inconclusive => Ok(HttpLookupObservation::Inconclusive(evidence_digest)),
        WireOutcome::Succeeded | WireOutcome::Rejected | WireOutcome::Ambiguous => invalid(),
    }
}

impl HttpTransport for StockHttpsEffectTransport {
    fn security(&self) -> Result<HttpTransportSecurity, EffectError> {
        Ok(self.security.clone())
    }

    fn validate_resource_binding(
        &self,
        request: &HttpResourceBindingRequest<'_>,
    ) -> Result<(), EffectError> {
        self.validate_scoped_body(request)
    }

    fn send(
        &self,
        request: &HttpTransportRequest<'_>,
    ) -> Result<HttpTransportObservation, EffectError> {
        self.validate_transport_boundary(request.endpoint(), request.pinned_addresses())?;
        let binding = send_binding(request)?;
        let not_sent = || {
            evidence(b"dispatch-definitely-not-sent", &binding)
                .map(HttpTransportObservation::RequestNotSent)
        };
        let ambiguous = || {
            evidence(b"dispatch-transport-ambiguous", &binding).map(|evidence_digest| {
                HttpTransportObservation::Ambiguous {
                    evidence_digest,
                    remote_operation_id: None,
                }
            })
        };
        let credential =
            match self.load_credential(Some(request.project_id()), Some(request.resource_id())) {
                Ok(credential) => credential,
                Err(_error) => return not_sent(),
            };
        let mut headers = common_headers(
            &credential,
            "dispatch",
            request.idempotency_scope(),
            request.idempotency_key().as_str(),
            request.arguments_digest(),
            request.attempt_id(),
            &binding,
        )?;
        headers.insert(CONTENT_TYPE, header_value(request.content_type())?);
        headers.insert(
            CIGAR_FENCING_TOKEN,
            header_value(&request.fencing_token().to_string())?,
        );
        headers.insert(
            CIGAR_REQUEST_DIGEST,
            header_value(request.request_digest().as_str())?,
        );
        headers.insert(
            CONTENT_LENGTH,
            header_value(&request.body().len().to_string())?,
        );
        let method = match request.method() {
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
        };
        let timeout = match self.remaining_timeout(request.deadline().unix_nanos()) {
            Ok(timeout) => timeout,
            Err(ExecutionFailure::DefinitelyNotSent) => return not_sent(),
            Err(ExecutionFailure::Ambiguous) => return ambiguous(),
        };
        let outbound = OutboundRequest {
            method,
            url: self.endpoint.url.clone(),
            headers,
            body: Some(request.body().to_vec()),
            timeout,
            maximum_response_bytes: self.configuration.maximum_response_bytes,
        };
        match self.execute(outbound) {
            Ok(response) => map_send_result(response, &binding),
            Err(ExecutionFailure::DefinitelyNotSent) => not_sent(),
            Err(ExecutionFailure::Ambiguous) => ambiguous(),
        }
    }

    fn lookup(&self, query: &HttpTransportQuery<'_>) -> Result<HttpLookupObservation, EffectError> {
        self.validate_transport_boundary(query.endpoint(), query.pinned_addresses())?;
        let binding = lookup_binding(query)?;
        let inconclusive = || {
            evidence(b"lookup-transport-inconclusive", &binding)
                .map(HttpLookupObservation::Inconclusive)
        };
        let credential =
            match self.load_credential(Some(query.project_id()), Some(query.resource_id())) {
                Ok(credential) => credential,
                Err(_error) => return inconclusive(),
            };
        let headers = common_headers(
            &credential,
            "lookup",
            query.idempotency_scope(),
            query.idempotency_key().as_str(),
            query.arguments_digest(),
            query.attempt_id(),
            &binding,
        )?;
        let timeout = match self.remaining_timeout(query.deadline().unix_nanos()) {
            Ok(timeout) => timeout,
            Err(ExecutionFailure::DefinitelyNotSent | ExecutionFailure::Ambiguous) => {
                return inconclusive();
            }
        };
        let outbound = OutboundRequest {
            method: Method::GET,
            url: self.endpoint.url.clone(),
            headers,
            body: None,
            timeout,
            maximum_response_bytes: self.configuration.maximum_response_bytes,
        };
        match self.execute(outbound) {
            Ok(response) => map_lookup_result(response, &binding),
            Err(ExecutionFailure::DefinitelyNotSent | ExecutionFailure::Ambiguous) => {
                inconclusive()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::error::Error;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    struct TestGate(AtomicBool);

    impl TestGate {
        fn open() -> Self {
            Self(AtomicBool::new(true))
        }

        fn close(&self) {
            self.0.store(false, Ordering::Release);
        }
    }

    impl EffectDispatchGate for TestGate {
        fn dispatch_claims_allowed(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    struct FixedExecutor {
        responses: Mutex<Vec<Result<OutboundResponse, ExecutionFailure>>>,
        requests: Mutex<Vec<OutboundRequest>>,
    }

    impl FixedExecutor {
        fn new(responses: Vec<Result<OutboundResponse, ExecutionFailure>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().rev().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpsExecutor for FixedExecutor {
        fn execute(&self, request: OutboundRequest) -> ExecutionFuture<'_> {
            let recorded = match self.requests.lock() {
                Ok(mut requests) => {
                    requests.push(request);
                    true
                }
                Err(_error) => false,
            };
            let response = self
                .responses
                .lock()
                .ok()
                .and_then(|mut responses| responses.pop())
                .unwrap_or(Err(ExecutionFailure::Ambiguous));
            Box::pin(async move {
                if !recorded {
                    Err(ExecutionFailure::Ambiguous)
                } else {
                    response
                }
            })
        }
    }

    struct PendingExecutor;

    impl HttpsExecutor for PendingExecutor {
        fn execute(&self, _request: OutboundRequest) -> ExecutionFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        _runtime: tokio::runtime::Runtime,
        gate: Arc<TestGate>,
        transport: StockHttpsEffectTransport,
        credential_path: PathBuf,
        project_id: RecordId,
        resource_id: String,
    }

    fn digest(byte: u8) -> TestResult<ContentDigest> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            format!("{byte:02x}").repeat(32)
        ))?)
    }

    struct TlsServer {
        address: SocketAddr,
        root_der: Vec<u8>,
        connections: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    fn spawn_tls_server(
        runtime: &tokio::runtime::Runtime,
        certificate_hostname: &str,
        response: &'static [u8],
    ) -> TestResult<TlsServer> {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new())?;
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = CertifiedIssuer::self_signed(ca_parameters, KeyPair::generate()?)?;
        let mut server_parameters = CertificateParams::new(vec![certificate_hostname.to_owned()])?;
        server_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_certificate = server_parameters.signed_by(&server_key, &ca)?;
        let root_der = ca.der().to_vec();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(server_certificate.der().to_vec()),
                    CertificateDer::from(root_der.clone()),
                ],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )?;
        let listener = runtime.block_on(tokio::net::TcpListener::bind((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))?;
        let address = listener.local_addr()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&connections);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let task = runtime.spawn(async move {
            let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
            let Ok(Ok((stream, _peer))) = accepted else {
                return;
            };
            observed.fetch_add(1, Ordering::SeqCst);
            let handshake =
                tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream)).await;
            let Ok(Ok(mut stream)) = handshake else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1_024];
            loop {
                let read =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
                let Ok(Ok(read)) = read else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let Some(chunk) = buffer.get(..read) else {
                    return;
                };
                request.extend_from_slice(chunk);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if request.len() > 16 * 1_024 {
                    return;
                }
            }
            if stream.write_all(response).await.is_ok() {
                let _shutdown_result = stream.shutdown().await;
            }
        });
        Ok(TlsServer {
            address,
            root_der,
            connections,
            task,
        })
    }

    fn tls_outbound(endpoint: &ParsedEndpoint) -> OutboundRequest {
        OutboundRequest {
            method: Method::GET,
            url: endpoint.url.clone(),
            headers: HeaderMap::new(),
            body: None,
            timeout: Duration::from_secs(2),
            maximum_response_bytes: 1_024,
        }
    }

    fn fixture(executor: Arc<dyn HttpsExecutor>) -> TestResult<Fixture> {
        let directory = tempfile::tempdir()?;
        // macOS exposes its temporary root through `/var`, which is a symlink to
        // `/private/var`.  Production secret reads intentionally reject every
        // symlinked ancestor, so exercise the same descriptor-safe path through
        // the canonical temporary directory.
        let credential_path =
            std::fs::canonicalize(directory.path())?.join("effect-credential.json");
        let project_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
        let resource_id = "resource-a".to_owned();
        let now = unix_now_nanos().map_err(|error| format!("clock: {error}"))?;
        let document = ScopedCredentialDocument {
            schema_version: CREDENTIAL_SCHEMA.to_owned(),
            handle: "credential-a".to_owned(),
            endpoint_origin: "https://effects.example.invalid".to_owned(),
            project_id: project_id.clone(),
            resource_id: resource_id.clone(),
            not_before_unix_nanos: now.saturating_sub(1_000_000_000),
            expires_at_unix_nanos: now.saturating_add(60_000_000_000),
            bearer_token: "a-secure-test-token-0123456789".to_owned(),
        };
        std::fs::write(&credential_path, serde_json::to_vec(&document)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))?;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let gate = Arc::new(TestGate::open());
        let dispatch_gate: Arc<dyn EffectDispatchGate> = gate.clone();
        let configuration = ProductionHttpsEffectTransportConfiguration {
            provider_protocol: STOCK_HTTPS_EFFECT_PROTOCOL.to_owned(),
            credential_handle: "credential-a".to_owned(),
            credential_file: credential_path.clone(),
            pinned_addresses: vec![std::net::Ipv4Addr::new(93, 184, 216, 34).into()],
            connect_timeout_ms: 1_000,
            request_timeout_ms: 2_000,
            maximum_response_bytes: 16 * 1_024,
        };
        let transport = StockHttpsEffectTransport::new_with_dependencies(
            "https://effects.example.invalid/v1/effects",
            configuration,
            runtime.handle().clone(),
            dispatch_gate,
            vec![SocketAddr::from(([93, 184, 216, 34], 443))],
            Some(executor),
        )?;
        Ok(Fixture {
            _directory: directory,
            _runtime: runtime,
            gate,
            transport,
            credential_path,
            project_id,
            resource_id,
        })
    }

    fn outbound_request(timeout: Duration) -> TestResult<OutboundRequest> {
        Ok(OutboundRequest {
            method: Method::POST,
            url: Url::parse("https://effects.example.invalid/v1/effects")?,
            headers: HeaderMap::new(),
            body: Some(vec![1, 2, 3]),
            timeout,
            maximum_response_bytes: 1_024,
        })
    }

    fn response(
        binding: ContentDigest,
        outcome: WireOutcome,
        remote_operation_id: Option<String>,
        response_digest: Option<ContentDigest>,
        verification_digest: Option<ContentDigest>,
        evidence_digest: Option<ContentDigest>,
    ) -> TestResult<OutboundResponse> {
        let body = serde_json::to_vec(&WireResult {
            schema_version: RESULT_SCHEMA.to_owned(),
            request_binding: binding,
            outcome,
            remote_operation_id,
            response_digest,
            verification_digest,
            evidence_digest,
        })?;
        Ok(OutboundResponse {
            status: StatusCode::OK,
            content_type: Some(HeaderValue::from_static(EFFECT_RESULT_MEDIA_TYPE)),
            body,
        })
    }

    #[test]
    fn real_tls_chain_hostname_and_redirect_policy_are_enforced() -> TestResult {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: https://attacker.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

        let valid = spawn_tls_server(&runtime, "effects.example.invalid", redirect)?;
        let endpoint = parse_endpoint(&format!(
            "https://effects.example.invalid:{}/v1/effects",
            valid.address.port()
        ))?;
        let executor = ReqwestHttpsExecutor::new_with_test_roots(
            &endpoint,
            &[valid.address],
            Duration::from_secs(1),
            std::slice::from_ref(&valid.root_der),
        )?;
        let observed = runtime.block_on(executor.execute(tls_outbound(&endpoint)));
        assert!(matches!(
            observed,
            Ok(OutboundResponse {
                status: StatusCode::FOUND,
                ..
            })
        ));
        runtime.block_on(valid.task)?;
        assert_eq!(valid.connections.load(Ordering::SeqCst), 1);

        let wrong_hostname = spawn_tls_server(&runtime, "effects.example.invalid", redirect)?;
        let endpoint = parse_endpoint(&format!(
            "https://other.example.invalid:{}/v1/effects",
            wrong_hostname.address.port()
        ))?;
        let executor = ReqwestHttpsExecutor::new_with_test_roots(
            &endpoint,
            &[wrong_hostname.address],
            Duration::from_secs(1),
            std::slice::from_ref(&wrong_hostname.root_der),
        )?;
        assert!(
            runtime
                .block_on(executor.execute(tls_outbound(&endpoint)))
                .is_err()
        );
        runtime.block_on(wrong_hostname.task)?;
        assert_eq!(wrong_hostname.connections.load(Ordering::SeqCst), 1);

        let wrong_chain = spawn_tls_server(&runtime, "effects.example.invalid", redirect)?;
        let unrelated =
            rcgen::generate_simple_self_signed(vec!["unrelated-root.example.invalid".to_owned()])?;
        let unrelated_root = unrelated.cert.der().to_vec();
        let endpoint = parse_endpoint(&format!(
            "https://effects.example.invalid:{}/v1/effects",
            wrong_chain.address.port()
        ))?;
        let executor = ReqwestHttpsExecutor::new_with_test_roots(
            &endpoint,
            &[wrong_chain.address],
            Duration::from_secs(1),
            &[unrelated_root],
        )?;
        assert!(
            runtime
                .block_on(executor.execute(tls_outbound(&endpoint)))
                .is_err()
        );
        runtime.block_on(wrong_chain.task)?;
        assert_eq!(wrong_chain.connections.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn endpoint_bounds_address_pins_and_debug_are_closed() -> TestResult {
        let directory = tempfile::tempdir()?;
        let configuration = ProductionHttpsEffectTransportConfiguration {
            provider_protocol: STOCK_HTTPS_EFFECT_PROTOCOL.to_owned(),
            credential_handle: "credential-a".to_owned(),
            credential_file: directory.path().join("credential"),
            pinned_addresses: vec![std::net::Ipv4Addr::new(93, 184, 216, 34).into()],
            connect_timeout_ms: 1_000,
            request_timeout_ms: 2_000,
            maximum_response_bytes: 4_096,
        };
        assert!(
            configuration
                .validate_for_endpoint("https://effects.example.invalid/v1/effects")
                .is_ok()
        );
        for endpoint in [
            "http://effects.example.invalid/v1/effects",
            "https://user@effects.example.invalid/v1/effects",
            "https://effects.example.invalid/v1/../effects",
            "https://effects.example.invalid/v1/effects?redirect=https://other.example",
            "https://127.0.0.1/v1/effects",
            "https://localhost/v1/effects",
            "https://Effects.example.invalid/v1/effects",
            "https://effects.example.invalid/v1//effects",
        ] {
            assert!(configuration.validate_for_endpoint(endpoint).is_err());
        }
        let debug = format!("{configuration:?}");
        assert!(!debug.contains("credential-a"));
        assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));

        let mut invalid_pins = configuration.clone();
        invalid_pins.provider_protocol = "provider-specific-v0".to_owned();
        assert!(
            invalid_pins
                .validate_for_endpoint("https://effects.example.invalid/v1/effects")
                .is_err()
        );
        invalid_pins.provider_protocol = STOCK_HTTPS_EFFECT_PROTOCOL.to_owned();
        invalid_pins.pinned_addresses = vec![std::net::Ipv4Addr::LOCALHOST.into()];
        assert!(
            invalid_pins
                .validate_for_endpoint("https://effects.example.invalid/v1/effects")
                .is_err()
        );
        invalid_pins.pinned_addresses = vec![
            std::net::Ipv4Addr::new(93, 184, 216, 35).into(),
            std::net::Ipv4Addr::new(93, 184, 216, 34).into(),
        ];
        assert!(
            invalid_pins
                .validate_for_endpoint("https://effects.example.invalid/v1/effects")
                .is_err()
        );

        let fake = Arc::new(FixedExecutor::new(Vec::new()));
        let fixture = fixture(fake.clone())?;
        let invalid = StockHttpsEffectTransport::new_with_dependencies(
            "https://effects.example.invalid/v1/effects",
            fixture.transport.configuration.clone(),
            fixture._runtime.handle().clone(),
            fixture.gate.clone(),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))],
            Some(fake),
        );
        assert!(matches!(
            invalid,
            Err(ProductionHttpsEffectTransportError::ResolutionUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn credential_and_scoped_body_are_exact_and_owner_private() -> TestResult {
        let fixture = fixture(Arc::new(FixedExecutor::new(Vec::new())))?;
        assert!(
            fixture
                .transport
                .load_credential(Some(&fixture.project_id), Some(&fixture.resource_id))
                .is_ok()
        );
        let credential = fixture
            .transport
            .load_credential(Some(&fixture.project_id), Some(&fixture.resource_id))?;
        assert!(credential.authorization_header()?.is_sensitive());
        assert!(
            fixture
                .transport
                .load_credential(Some(&fixture.project_id), Some("resource-b"))
                .is_err()
        );
        let body = serde_json::to_vec(&ScopedEffectBody {
            schema_version: SCOPED_BODY_SCHEMA.to_owned(),
            project_id: fixture.project_id.clone(),
            resource_id: fixture.resource_id.clone(),
            payload: serde_json::json!({"command":"perform"}),
        })?;
        assert!(
            validate_scoped_document(
                SCOPED_EFFECT_BODY_MEDIA_TYPE,
                &body,
                &fixture.project_id,
                &fixture.resource_id,
            )
            .is_ok()
        );
        assert!(
            validate_scoped_document(
                "application/json",
                &body,
                &fixture.project_id,
                &fixture.resource_id,
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                &fixture.credential_path,
                std::fs::Permissions::from_mode(0o644),
            )?;
            assert!(fixture.transport.load_credential(None, None).is_err());
        }
        Ok(())
    }

    #[test]
    fn cancellation_and_transport_failures_preserve_ambiguity() -> TestResult {
        let pending = Arc::new(PendingExecutor);
        let pending_fixture = fixture(pending)?;
        let gate = Arc::clone(&pending_fixture.gate);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            gate.close();
        });
        assert!(matches!(
            pending_fixture
                .transport
                .execute(outbound_request(Duration::from_secs(1))?),
            Err(ExecutionFailure::Ambiguous)
        ));
        closer.join().map_err(|_panic| "gate closer panicked")?;

        let not_sent = Arc::new(FixedExecutor::new(vec![Err(
            ExecutionFailure::DefinitelyNotSent,
        )]));
        let not_sent_fixture = fixture(not_sent)?;
        assert!(matches!(
            not_sent_fixture
                .transport
                .execute(outbound_request(Duration::from_secs(1))?),
            Err(ExecutionFailure::DefinitelyNotSent)
        ));
        Ok(())
    }

    #[test]
    fn strict_wire_results_separate_dispatch_and_lookup_outcomes() -> TestResult {
        let binding = digest(1)?;
        let dispatch = response(
            binding.clone(),
            WireOutcome::Succeeded,
            Some("operation-1".to_owned()),
            Some(digest(2)?),
            Some(digest(3)?),
            None,
        )?;
        assert!(matches!(
            map_send_result(dispatch, &binding)?,
            HttpTransportObservation::Succeeded { .. }
        ));
        let lookup = response(
            binding.clone(),
            WireOutcome::ProvenNotExecuted,
            None,
            None,
            None,
            Some(digest(4)?),
        )?;
        assert!(matches!(
            map_lookup_result(lookup, &binding)?,
            HttpLookupObservation::ProvenNotExecuted(_)
        ));
        let wrong_channel = response(
            binding.clone(),
            WireOutcome::ConfirmedSuccess,
            None,
            None,
            None,
            Some(digest(5)?),
        )?;
        assert!(matches!(
            map_send_result(wrong_channel, &binding)?,
            HttpTransportObservation::Ambiguous { .. }
        ));
        let invalid = OutboundResponse {
            status: StatusCode::TEMPORARY_REDIRECT,
            content_type: None,
            body: b"https://attacker.invalid".to_vec(),
        };
        assert!(matches!(
            map_send_result(invalid, &binding)?,
            HttpTransportObservation::Ambiguous { .. }
        ));
        Ok(())
    }
}
