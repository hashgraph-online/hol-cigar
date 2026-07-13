//! Object-safe operation client and bounded HTTP/JSON implementation.

use crate::arguments::TargetKind;
use crate::configuration::EffectiveConfiguration;
use crate::error::CliError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::{HttpMethod, OperationContract};
use cigar_api::{
    AuthenticatedIdentity, CancellationToken, OperationId, PathParameter, RequestContext,
    RequestEnvelope, ResponseEnvelope, TraceId,
};
use cigar_canon::{from_deterministic_cbor, parse_strict_json, to_normalized_json};
use cigar_protocol::Problem;
use reqwest::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderMap, HeaderName, HeaderValue, IF_MATCH,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const HEADER_OPERATION_ID: &str = "x-cigar-operation-id";
const HEADER_TIMEOUT_MS: &str = "x-cigar-timeout-ms";
const HEADER_IDEMPOTENCY_KEY: &str = "idempotency-key";
const HEADER_NEXT_PAGE_CURSOR: &str = "x-cigar-next-page-cursor";

pub(crate) struct OperationRequest {
    pub(crate) contract: &'static OperationContract,
    pub(crate) payload_cbor: Vec<u8>,
    pub(crate) path_parameters: Vec<(String, String)>,
    pub(crate) dry_run: bool,
    pub(crate) idempotency_key: Option<String>,
    pub(crate) expected_revision: Option<String>,
    pub(crate) page_cursor: Option<String>,
    pub(crate) page_size: Option<u32>,
    pub(crate) deadline: Duration,
    pub(crate) authorization: Option<String>,
}

pub(crate) struct OperationResponse {
    pub(crate) operation_id: String,
    pub(crate) result: Value,
    pub(crate) semantic_etag: Option<String>,
    pub(crate) next_page_cursor: Option<String>,
}

pub(crate) trait OperationClient: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResponse, CliError>> + Send + 'a>>;
}

pub(crate) struct HttpOperationClient {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}

pub(crate) struct EmbeddedOperationClient {
    running: cigar_daemon::RunningEmbeddedDaemon,
    identity: AuthenticatedIdentity,
}

impl EmbeddedOperationClient {
    pub(crate) async fn start(configuration: &EffectiveConfiguration) -> Result<Self, CliError> {
        let path = configuration
            .daemon_config()
            .ok_or_else(CliError::invalid_configuration)?;
        let config = cigar_daemon::load_configuration(path)
            .map_err(|_error| CliError::invalid_configuration())?;
        if config.mode != cigar_daemon::DeploymentMode::Local {
            return Err(CliError::invalid_configuration());
        }
        let identity =
            cigar_daemon::LocalIdentity::from_project_root(&config.production.project_directory)
                .map_err(|_error| CliError::credential_unavailable())?
                .authenticated();
        let server = cigar_daemon::compose_production_server(config)
            .map_err(|_error| CliError::target_unavailable())?;
        let running = server
            .start_embedded()
            .await
            .map_err(|_error| CliError::target_unavailable())?;
        Ok(Self { running, identity })
    }

    pub(crate) async fn shutdown(&self) -> Result<(), CliError> {
        self.running
            .shutdown()
            .await
            .map(|_receipt| ())
            .map_err(|_error| CliError::target_unavailable())
    }

    async fn execute_embedded(
        &self,
        request: OperationRequest,
    ) -> Result<OperationResponse, CliError> {
        let cancellation = CancellationToken::new();
        let call = self.call_embedded(request, cancellation.clone());
        let result = tokio::time::timeout(call.deadline, call.future).await;
        let result = match result {
            Ok(result) => result,
            Err(_elapsed) => {
                cancellation.cancel();
                Err(CliError::deadline_exceeded())
            }
        };
        self.shutdown().await?;
        result
    }

    fn call_embedded<'a>(
        &'a self,
        request: OperationRequest,
        cancellation: CancellationToken,
    ) -> EmbeddedCall<'a> {
        let deadline = request.deadline;
        let future = Box::pin(async move {
            let path_parameters = request
                .path_parameters
                .into_iter()
                .map(|(name, value)| PathParameter::new(name, value))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_error| CliError::invalid_input())?;
            let envelope = RequestEnvelope::new_with_dry_run(
                request.contract.operation_id,
                request.payload_cbor,
                request.dry_run,
                request.idempotency_key,
                request.expected_revision,
                request.page_cursor,
                request.page_size,
                path_parameters,
            )
            .map_err(|_error| CliError::invalid_input())?;
            let (accepted, deadline_at) = request_times(deadline)?;
            let context = RequestContext::new(
                self.identity.clone(),
                OperationId::new(request.contract.operation_id)
                    .map_err(|_error| CliError::invalid_input())?,
                deadline_at,
                random_trace_id()?,
                cancellation,
                accepted,
            )
            .map_err(|_error| CliError::invalid_input())?;
            let response = self
                .running
                .facade()
                .call(context, envelope)
                .await
                .map_err(api_error)?;
            decode_embedded_response(request.contract, response)
        });
        EmbeddedCall { deadline, future }
    }
}

struct EmbeddedCall<'a> {
    deadline: Duration,
    future: Pin<Box<dyn Future<Output = Result<OperationResponse, CliError>> + Send + 'a>>,
}

impl HttpOperationClient {
    pub(crate) fn new(configuration: &EffectiveConfiguration) -> Result<Self, CliError> {
        if configuration.target() == TargetKind::Embedded {
            return Err(CliError::unsupported_target());
        }
        let _provider = rustls::crypto::ring::default_provider().install_default();
        let endpoint_value = if configuration.local_socket().is_some()
            || configuration.windows_named_pipe().is_some()
        {
            "http://localhost"
        } else {
            configuration.endpoint()?
        };
        let endpoint = reqwest::Url::parse(endpoint_value)
            .map_err(|_error| CliError::invalid_configuration())?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .referer(false);
        #[cfg(unix)]
        if let Some(socket) = configuration.local_socket() {
            validate_unix_socket(socket)?;
            builder = builder.unix_socket(socket);
        }
        #[cfg(windows)]
        if let Some(pipe) = configuration.windows_named_pipe() {
            builder = builder.windows_named_pipe(pipe);
        }
        let client = builder
            .build()
            .map_err(|_error| CliError::target_unavailable())?;
        Ok(Self { client, endpoint })
    }

    async fn execute_http(&self, request: OperationRequest) -> Result<OperationResponse, CliError> {
        let url = operation_url(&self.endpoint, &request)?;
        let mut builder = match request.contract.http_method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => {
                let body = serde_json::to_vec(&HttpOperationRequest {
                    operation_id: request.contract.operation_id,
                    payload_cbor: URL_SAFE_NO_PAD.encode(&request.payload_cbor),
                    dry_run: request.dry_run,
                    idempotency_key: request.idempotency_key.as_deref(),
                    expected_revision: request.expected_revision.as_deref(),
                    page_cursor: request.page_cursor.as_deref(),
                    page_size: request.page_size,
                    path_parameters: request
                        .path_parameters
                        .iter()
                        .map(|(name, value)| HttpPathParameter { name, value })
                        .collect(),
                })
                .map_err(|_error| CliError::invalid_input())?;
                self.client
                    .post(url)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
            }
        };
        builder = builder
            .header(HEADER_OPERATION_ID, request.contract.operation_id)
            .header(HEADER_TIMEOUT_MS, request.deadline.as_millis().to_string())
            .timeout(request.deadline);
        if let Some(value) = &request.authorization {
            let value = HeaderValue::from_str(value)
                .map_err(|_error| CliError::credential_unavailable())?;
            builder = builder.header(AUTHORIZATION, value);
        }
        if let Some(value) = &request.idempotency_key {
            builder = builder.header(HEADER_IDEMPOTENCY_KEY, value);
        }
        if let Some(value) = &request.expected_revision {
            builder = builder.header(IF_MATCH, value);
        }
        let response = tokio::time::timeout(request.deadline, builder.send())
            .await
            .map_err(|_elapsed| CliError::deadline_exceeded())?
            .map_err(|error| {
                if error.is_timeout() {
                    CliError::deadline_exceeded()
                } else {
                    CliError::target_unavailable()
                }
            })?;
        let status = response.status();
        let headers = response.headers().clone();
        validate_content_length(&headers)?;
        let bytes = read_bounded_response(response).await?;
        if !status.is_success() {
            validate_problem_content_type(&headers)?;
            return Err(problem_error(status.as_u16(), &bytes));
        }
        validate_json_content_type(&headers)?;
        parse_strict_json(&bytes).map_err(|_error| CliError::invalid_response())?;
        let wire: HttpOperationResponse =
            serde_json::from_slice(&bytes).map_err(|_error| CliError::invalid_response())?;
        if wire.operation_id != request.contract.operation_id {
            return Err(CliError::stale_daemon());
        }
        let payload = URL_SAFE_NO_PAD
            .decode(wire.payload_cbor.as_bytes())
            .map_err(|_error| CliError::invalid_response())?;
        if payload.len() > MAX_RESPONSE_BYTES {
            return Err(CliError::invalid_response());
        }
        let node =
            from_deterministic_cbor(&payload).map_err(|_error| CliError::invalid_response())?;
        let normalized =
            to_normalized_json(&node).map_err(|_error| CliError::invalid_response())?;
        let result =
            serde_json::from_slice(&normalized).map_err(|_error| CliError::invalid_response())?;
        let header_etag = header_string(&headers, ETAG)?;
        let header_cursor =
            header_string(&headers, HeaderName::from_static(HEADER_NEXT_PAGE_CURSOR))?;
        if header_etag.as_deref() != wire.semantic_etag.as_deref()
            || header_cursor.as_deref() != wire.next_page_cursor.as_deref()
        {
            return Err(CliError::invalid_response());
        }
        Ok(OperationResponse {
            operation_id: wire.operation_id,
            result,
            semantic_etag: wire.semantic_etag,
            next_page_cursor: wire.next_page_cursor,
        })
    }
}

#[cfg(unix)]
fn validate_unix_socket(path: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata =
        std::fs::symlink_metadata(path).map_err(|_error| CliError::target_unavailable())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.mode() & 0o077 != 0
    {
        return Err(CliError::target_unavailable());
    }
    let parent = path.parent().ok_or_else(CliError::target_unavailable)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_error| CliError::target_unavailable())?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o077 != 0
        || parent_metadata.uid() != metadata.uid()
    {
        return Err(CliError::target_unavailable());
    }
    Ok(())
}

impl OperationClient for HttpOperationClient {
    fn execute<'a>(
        &'a self,
        request: OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResponse, CliError>> + Send + 'a>> {
        Box::pin(self.execute_http(request))
    }
}

impl OperationClient for EmbeddedOperationClient {
    fn execute<'a>(
        &'a self,
        request: OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<OperationResponse, CliError>> + Send + 'a>> {
        Box::pin(self.execute_embedded(request))
    }
}

fn request_times(
    deadline: Duration,
) -> Result<(cigar_protocol::UtcTimestamp, cigar_protocol::UtcTimestamp), CliError> {
    let accepted_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
        .ok_or_else(CliError::target_unavailable)?;
    let deadline_delta =
        i128::try_from(deadline.as_nanos()).map_err(|_error| CliError::invalid_command())?;
    let deadline_nanos = accepted_nanos
        .checked_add(deadline_delta)
        .ok_or_else(CliError::invalid_command)?;
    let accepted = cigar_protocol::UtcTimestamp::from_unix_nanos(accepted_nanos)
        .map_err(|_error| CliError::target_unavailable())?;
    let deadline_at = cigar_protocol::UtcTimestamp::from_unix_nanos(deadline_nanos)
        .map_err(|_error| CliError::invalid_command())?;
    Ok((accepted, deadline_at))
}

fn random_trace_id() -> Result<TraceId, CliError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_error| CliError::target_unavailable())?;
    if bytes.iter().all(|byte| *byte == 0)
        && let Some(last) = bytes.last_mut()
    {
        *last = 1;
    }
    let value = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    TraceId::new(value).map_err(|_error| CliError::target_unavailable())
}

fn api_error(error: cigar_api::ApiError) -> CliError {
    let definition = error.code().definition();
    CliError::from_public_problem(
        definition.symbol,
        definition.message,
        definition.remediation,
        definition.http_status,
    )
}

fn decode_embedded_response(
    contract: &'static OperationContract,
    response: ResponseEnvelope,
) -> Result<OperationResponse, CliError> {
    if response.operation_id().as_str() != contract.operation_id {
        return Err(CliError::stale_daemon());
    }
    let payload = response.payload_cbor();
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(CliError::invalid_response());
    }
    let node = from_deterministic_cbor(payload).map_err(|_error| CliError::invalid_response())?;
    let normalized = to_normalized_json(&node).map_err(|_error| CliError::invalid_response())?;
    let result =
        serde_json::from_slice(&normalized).map_err(|_error| CliError::invalid_response())?;
    Ok(OperationResponse {
        operation_id: contract.operation_id.to_owned(),
        result,
        semantic_etag: response.semantic_etag().map(str::to_owned),
        next_page_cursor: response.next_page_cursor().map(str::to_owned),
    })
}

#[derive(Serialize)]
struct HttpOperationRequest<'a> {
    operation_id: &'a str,
    payload_cbor: String,
    dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_size: Option<u32>,
    path_parameters: Vec<HttpPathParameter<'a>>,
}

#[derive(Serialize)]
struct HttpPathParameter<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpOperationResponse {
    operation_id: String,
    payload_cbor: String,
    semantic_etag: Option<String>,
    next_page_cursor: Option<String>,
}

fn operation_url(
    endpoint: &reqwest::Url,
    request: &OperationRequest,
) -> Result<reqwest::Url, CliError> {
    let mut path = request.contract.http_path.to_owned();
    for (name, value) in &request.path_parameters {
        path = path.replace(&format!("{{{name}}}"), value);
    }
    if path.contains('{') || path.contains('}') {
        return Err(CliError::invalid_input());
    }
    let mut url = endpoint.clone();
    url.set_path(&path);
    if request.contract.http_method == HttpMethod::Get
        && (request.page_cursor.is_some() || request.page_size.is_some())
    {
        let mut query = url.query_pairs_mut();
        if let Some(cursor) = &request.page_cursor {
            query.append_pair("page_cursor", cursor);
        }
        if let Some(page_size) = request.page_size {
            query.append_pair("page_size", &page_size.to_string());
        }
    }
    Ok(url)
}

fn validate_content_length(headers: &HeaderMap) -> Result<(), CliError> {
    if let Some(value) = headers.get(CONTENT_LENGTH) {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(CliError::invalid_response)?;
        if length > MAX_RESPONSE_BYTES {
            return Err(CliError::invalid_response());
        }
    }
    Ok(())
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), CliError> {
    let valid = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if valid {
        Ok(())
    } else {
        Err(CliError::invalid_response())
    }
}

fn validate_problem_content_type(headers: &HeaderMap) -> Result<(), CliError> {
    let valid = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/problem+json")
        });
    if valid {
        Ok(())
    } else {
        Err(CliError::invalid_response())
    }
}

async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_error| CliError::target_unavailable())?
    {
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or_else(CliError::invalid_response)?;
        bytes.reserve(next.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn problem_error(status: u16, bytes: &[u8]) -> CliError {
    if parse_strict_json(bytes).is_err() {
        return CliError::invalid_response();
    }
    let Ok(problem) = serde_json::from_slice::<Problem>(bytes) else {
        return CliError::invalid_response();
    };
    let definition = problem.code.definition();
    if problem.http_status != status || definition.http_status != status {
        return CliError::invalid_response();
    }
    CliError::from_public_problem(
        definition.symbol,
        definition.message,
        definition.remediation,
        status,
    )
}

fn header_string(
    headers: &HeaderMap,
    name: impl reqwest::header::AsHeaderName,
) -> Result<Option<String>, CliError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_error| CliError::invalid_response())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::operation_url;
    use crate::client::OperationRequest;
    use cigar_api::generated::operation_by_id;
    use std::time::Duration;

    #[test]
    fn operation_urls_bind_only_unreserved_path_values() -> Result<(), Box<dyn std::error::Error>> {
        let contract = operation_by_id("getEffectStatus").ok_or("missing operation")?;
        let request = OperationRequest {
            contract,
            payload_cbor: Vec::new(),
            path_parameters: vec![("effect_id".to_owned(), "effect-1".to_owned())],
            dry_run: false,
            idempotency_key: None,
            expected_revision: None,
            page_cursor: None,
            page_size: None,
            deadline: Duration::from_secs(1),
            authorization: None,
        };
        let endpoint = reqwest::Url::parse("https://example.test")?;
        assert_eq!(
            operation_url(&endpoint, &request)?.as_str(),
            "https://example.test/v1/effects/effect-1"
        );
        Ok(())
    }
}
