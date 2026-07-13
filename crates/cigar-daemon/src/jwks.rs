//! Bounded same-origin HTTPS OIDC discovery and JWKS refresh.

use crate::{
    AuthenticationError, AuthenticationErrorCode, JwksRefresh, JwksRefreshFuture,
    JwksRefreshRequest, JwksRefreshResponse,
};
use cigar_canon::{CanonicalNode, parse_strict_json};
use reqwest::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Client, StatusCode, Url};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_DISCOVERY_TEXT_BYTES: usize = 2_048;
const MAX_HTTP_CACHE_AGE_SECONDS: u64 = 604_800;
const DEFAULT_UNCACHED_LIFETIME_SECONDS: u64 = 1;

/// Stable construction failure for the concrete HTTPS refresh provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsJwksRefreshBuildError {
    /// A proxy-free, redirect-free, platform-verifying HTTPS client could not be built.
    ClientUnavailable,
}

impl fmt::Display for HttpsJwksRefreshBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HTTPS JWKS refresh client is unavailable")
    }
}

impl std::error::Error for HttpsJwksRefreshBuildError {}

/// Concrete OIDC discovery/JWKS provider with redirects and ambient proxies disabled.
#[derive(Clone)]
pub struct HttpsJwksRefresh {
    client: Client,
}

impl HttpsJwksRefresh {
    /// Builds a platform-root-verifying HTTPS client without proxy or redirect authority.
    pub fn new() -> Result<Self, HttpsJwksRefreshBuildError> {
        // `reqwest` is deliberately built with `rustls-no-provider` so the
        // workspace, rather than a transitive dependency, selects the crypto
        // implementation. Installation is process-global and idempotent: an
        // already-installed provider (including one chosen by an embedding
        // application) remains authoritative.
        let _provider_result = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .tcp_nodelay(true)
            .pool_max_idle_per_host(2)
            .user_agent("cigard-oidc-jwks/1")
            .build()
            .map_err(|_error| HttpsJwksRefreshBuildError::ClientUnavailable)?;
        Ok(Self { client })
    }
}

impl JwksRefresh for HttpsJwksRefresh {
    fn refresh(&self, request: JwksRefreshRequest) -> JwksRefreshFuture {
        let client = self.client.clone();
        Box::pin(async move { refresh(&client, request).await })
    }
}

impl fmt::Debug for HttpsJwksRefresh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsJwksRefresh([PLATFORM ROOTS, NO PROXY, NO REDIRECTS])")
    }
}

async fn refresh(
    client: &Client,
    request: JwksRefreshRequest,
) -> Result<JwksRefreshResponse, AuthenticationError> {
    if request.timeout.is_zero() || request.max_response_bytes == 0 {
        return Err(unavailable());
    }
    let issuer = validated_https_url(&request.issuer)?;
    let discovery = discovery_url(&issuer)?;
    let (discovery_bytes, _discovery_cache_age) = get_bounded_json(
        client,
        discovery,
        request.timeout,
        request.max_response_bytes,
    )
    .await?;
    let jwks_uri = parse_discovery(&discovery_bytes, &request.issuer)?;
    let jwks = validated_https_url(&jwks_uri)?;
    if !same_origin(&issuer, &jwks) {
        return Err(unavailable());
    }
    let (document, cache_age) =
        get_bounded_json(client, jwks, request.timeout, request.max_response_bytes).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| unavailable())?
        .as_secs();
    let valid_until = now
        .checked_add(cache_age.max(DEFAULT_UNCACHED_LIFETIME_SECONDS))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(unavailable)?;
    Ok(JwksRefreshResponse {
        document,
        valid_until_unix_seconds: valid_until,
    })
}

fn validated_https_url(value: &str) -> Result<Url, AuthenticationError> {
    if value.is_empty()
        || value.len() > MAX_DISCOVERY_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(unavailable());
    }
    let url = Url::parse(value).map_err(|_error| unavailable())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(unavailable());
    }
    Ok(url)
}

fn discovery_url(issuer: &Url) -> Result<Url, AuthenticationError> {
    let mut discovery = issuer.clone();
    let path = issuer.path().trim_end_matches('/');
    discovery.set_path(&format!("{path}/.well-known/openid-configuration"));
    discovery.set_query(None);
    discovery.set_fragment(None);
    Ok(discovery)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn parse_discovery(bytes: &[u8], issuer: &str) -> Result<String, AuthenticationError> {
    let document = parse_strict_json(bytes).map_err(|_error| unavailable())?;
    let CanonicalNode::Map(fields) = document else {
        return Err(unavailable());
    };
    let exact_issuer = bounded_text(fields.get("issuer"))?;
    let jwks_uri = bounded_text(fields.get("jwks_uri"))?;
    if exact_issuer != issuer {
        return Err(unavailable());
    }
    Ok(jwks_uri.to_owned())
}

fn bounded_text(value: Option<&CanonicalNode>) -> Result<&str, AuthenticationError> {
    match value {
        Some(CanonicalNode::Text(value))
            if !value.is_empty()
                && value.len() <= MAX_DISCOVERY_TEXT_BYTES
                && !value.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Ok(value)
        }
        _ => Err(unavailable()),
    }
}

async fn get_bounded_json(
    client: &Client,
    url: Url,
    timeout: Duration,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, u64), AuthenticationError> {
    let mut response = client
        .get(url)
        .timeout(timeout)
        .header("accept", "application/json, application/jwk-set+json")
        .send()
        .await
        .map_err(|_error| unavailable())?;
    if response.status() != StatusCode::OK || !json_content_type(response.headers()) {
        return Err(unavailable());
    }
    if response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(unavailable());
    }
    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if content_length.is_some_and(|length| length > maximum_bytes) {
        return Err(unavailable());
    }
    let cache_age = cache_age_seconds(response.headers());
    let mut document = Vec::with_capacity(content_length.unwrap_or(0).min(maximum_bytes));
    while let Some(chunk) = response.chunk().await.map_err(|_error| unavailable())? {
        let next = document
            .len()
            .checked_add(chunk.len())
            .ok_or_else(unavailable)?;
        if next > maximum_bytes {
            return Err(unavailable());
        }
        document.extend_from_slice(&chunk);
    }
    if document.is_empty() {
        return Err(unavailable());
    }
    Ok((document, cache_age))
}

fn json_content_type(headers: &reqwest::header::HeaderMap) -> bool {
    let Some(value) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media_type = value.split(';').next().map(str::trim);
    matches!(
        media_type,
        Some("application/json" | "application/jwk-set+json")
    )
}

fn cache_age_seconds(headers: &reqwest::header::HeaderMap) -> u64 {
    let maximum = headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("max-age")
                .then(|| value.trim().trim_matches('"').parse::<u64>().ok())
                .flatten()
        })
        .min();
    maximum
        .unwrap_or(DEFAULT_UNCACHED_LIFETIME_SECONDS)
        .min(MAX_HTTP_CACHE_AGE_SECONDS)
}

const fn unavailable() -> AuthenticationError {
    AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_UNCACHED_LIFETIME_SECONDS, HttpsJwksRefresh, cache_age_seconds, discovery_url,
        parse_discovery, same_origin, validated_https_url,
    };
    use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue};

    #[test]
    fn discovery_is_exact_duplicate_safe_and_same_origin_pinned()
    -> Result<(), Box<dyn std::error::Error>> {
        let issuer = validated_https_url("https://issuer.example/tenant")?;
        assert_eq!(
            discovery_url(&issuer)?.as_str(),
            "https://issuer.example/tenant/.well-known/openid-configuration"
        );
        let document = br#"{
            "issuer":"https://issuer.example/tenant",
            "jwks_uri":"https://issuer.example/keys",
            "authorization_endpoint":"https://issuer.example/authorize"
        }"#;
        let jwks = parse_discovery(document, "https://issuer.example/tenant")?;
        assert!(same_origin(&issuer, &validated_https_url(&jwks)?));
        assert!(!same_origin(
            &issuer,
            &validated_https_url("https://keys.example/jwks")?
        ));
        assert!(
            parse_discovery(
                br#"{"issuer":"https://issuer.example/tenant","issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys"}"#,
                "https://issuer.example/tenant"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn unsafe_urls_and_unbounded_cache_directives_fail_or_clamp()
    -> Result<(), Box<dyn std::error::Error>> {
        for invalid in [
            "http://issuer.example",
            "https://user@issuer.example",
            "https://issuer.example?redirect=bad",
            "https://issuer.example#fragment",
        ] {
            assert!(validated_https_url(invalid).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=999999999"),
        );
        assert_eq!(cache_age_seconds(&headers), 604_800);
        headers.clear();
        assert_eq!(
            cache_age_seconds(&headers),
            DEFAULT_UNCACHED_LIFETIME_SECONDS
        );
        let _provider = HttpsJwksRefresh::new()?;
        Ok(())
    }
}
