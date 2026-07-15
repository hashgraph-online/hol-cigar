//! Local bearer and pinned OIDC authentication boundaries.

use crate::config::OidcSettings;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::{AuthenticatedIdentity, PrincipalId, RequestContextError, TenantId};
use cigar_canon::{CanonicalNode, parse_strict_json};
use cigar_crypto::verify_ed25519;
use cigar_protocol::ErrorCode;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const LOCAL_TOKEN_BYTES: usize = 32;
const MAX_LOCAL_TOKEN_TEXT_BYTES: usize = 128;
const MAX_JWKS_BYTES: usize = 65_536;
const MAX_JWKS_KEYS: usize = 64;
const MAX_KID_BYTES: usize = 128;
const MAX_CLAIM_TEXT_BYTES: usize = 2_048;
const MAX_AUDIENCES: usize = 32;

/// Stable authentication failure category with no credential content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationErrorCode {
    /// Authorization material was absent or structurally malformed.
    InvalidCredential,
    /// Token algorithm, signature, or key metadata was invalid.
    SignatureRejected,
    /// Issuer, audience, tenant, or service-certificate binding did not match.
    ScopeMismatch,
    /// Token was expired, not yet valid, or issued beyond accepted skew.
    TemporalInvalid,
    /// JWKS data was stale, unavailable, oversized, or malformed.
    KeySetUnavailable,
    /// Local credential file permissions or type were unsafe.
    UnsafeCredentialFile,
    /// OS randomness or credential persistence failed.
    CredentialIo,
    /// A safe server-side local user/project identity could not be resolved.
    LocalIdentityUnavailable,
}

/// Content-free authentication failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticationError {
    code: AuthenticationErrorCode,
}

impl AuthenticationError {
    pub(crate) const fn new(code: AuthenticationErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable internal authentication category.
    #[must_use]
    pub const fn code(self) -> AuthenticationErrorCode {
        self.code
    }

    /// Returns the stable public API category without reflecting credentials.
    #[must_use]
    pub const fn public_code(self) -> ErrorCode {
        match self.code {
            AuthenticationErrorCode::ScopeMismatch => ErrorCode::PolicyDenied,
            AuthenticationErrorCode::InvalidCredential
            | AuthenticationErrorCode::SignatureRejected
            | AuthenticationErrorCode::TemporalInvalid
            | AuthenticationErrorCode::KeySetUnavailable
            | AuthenticationErrorCode::UnsafeCredentialFile
            | AuthenticationErrorCode::CredentialIo
            | AuthenticationErrorCode::LocalIdentityUnavailable => ErrorCode::UnknownPrincipal,
        }
    }
}

impl fmt::Debug for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "authentication failed: {:?}", self.code)
    }
}

impl std::error::Error for AuthenticationError {}

impl From<RequestContextError> for AuthenticationError {
    fn from(_error: RequestContextError) -> Self {
        Self::new(AuthenticationErrorCode::ScopeMismatch)
    }
}

/// Random local-loopback bearer token with redacted formatting and zeroizing drop.
pub struct LocalBearerToken([u8; LOCAL_TOKEN_BYTES]);

impl LocalBearerToken {
    /// Creates a new token from operating-system randomness.
    pub fn generate() -> Result<Self, AuthenticationError> {
        let mut bytes = [0_u8; LOCAL_TOKEN_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))?;
        Ok(Self(bytes))
    }

    /// Generates and durably creates a new credential file without overwriting.
    pub fn create_file(path: &Path) -> Result<Self, AuthenticationError> {
        validate_credential_parent(path)?;
        let token = Self::generate()?;
        let mut file = create_credential_file(path)?;
        file.write_all(token.encoded().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))?;
        drop(file);
        validate_credential_file(path)?;
        Ok(token)
    }

    /// Loads an existing token only from a regular permission-restricted file.
    pub fn read_file(path: &Path) -> Result<Self, AuthenticationError> {
        validate_credential_parent(path)?;
        let file = open_validated_credential_file(path)?;
        let mut encoded = String::new();
        file.take((MAX_LOCAL_TOKEN_TEXT_BYTES + 1) as u64)
            .read_to_string(&mut encoded)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))?;
        if encoded.len() > MAX_LOCAL_TOKEN_TEXT_BYTES {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::InvalidCredential,
            ));
        }
        Self::decode(&encoded)
    }

    /// Verifies an exact HTTP bearer credential in constant time.
    pub fn authenticate(
        &self,
        authorization: &str,
        identity: &LocalIdentity,
    ) -> Result<AuthenticatedIdentity, AuthenticationError> {
        let encoded = authorization
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthenticationError::new(AuthenticationErrorCode::InvalidCredential))?;
        let candidate = Self::decode(encoded)?;
        if constant_time_equal(&self.0, &candidate.0) {
            Ok(identity.authenticated())
        } else {
            Err(AuthenticationError::new(
                AuthenticationErrorCode::InvalidCredential,
            ))
        }
    }

    fn decode(encoded: &str) -> Result<Self, AuthenticationError> {
        if encoded.is_empty()
            || encoded.len() > MAX_LOCAL_TOKEN_TEXT_BYTES
            || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::InvalidCredential,
            ));
        }
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::InvalidCredential)
        })?;
        let bytes: [u8; LOCAL_TOKEN_BYTES] = decoded.try_into().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::InvalidCredential)
        })?;
        Ok(Self(bytes))
    }

    fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl Drop for LocalBearerToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for LocalBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalBearerToken([REDACTED])")
    }
}

/// Server-resolved local user identity; never supplied by an HTTP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalIdentity {
    tenant: TenantId,
    principal: PrincipalId,
    #[cfg(windows)]
    windows_owner_sid: Option<Arc<str>>,
}

impl LocalIdentity {
    /// Creates a validated server-side local identity.
    pub fn new(
        tenant: impl Into<String>,
        principal: impl Into<String>,
    ) -> Result<Self, AuthenticationError> {
        Ok(Self {
            tenant: TenantId::new(tenant)?,
            principal: PrincipalId::new(principal)?,
            #[cfg(windows)]
            windows_owner_sid: None,
        })
    }

    /// Returns the verified transport-neutral identity derived by this server-side resolver.
    ///
    /// Embedded callers use this clone to construct the same request context as local IPC. The
    /// tenant and principal remain opaque validated values and are never accepted from request
    /// payloads or headers.
    #[must_use]
    pub fn authenticated(&self) -> AuthenticatedIdentity {
        AuthenticatedIdentity::from_verified_credentials(
            self.tenant.clone(),
            self.principal.clone(),
        )
    }

    /// Resolves a stable project tenant and filesystem-owner principal from a canonical directory.
    /// No request header, environment variable, or caller-supplied identity string is trusted.
    #[cfg(unix)]
    pub fn from_project_root(project_root: &Path) -> Result<Self, AuthenticationError> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;

        if !project_root.is_absolute() {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let canonical = project_root.canonicalize().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
        if canonical != project_root {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let metadata = std::fs::symlink_metadata(project_root).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"cigar.local-project-tenant.v1\0");
        hasher.update(canonical.as_os_str().as_bytes());
        let digest = hasher.finalize();
        let mut tenant = String::from("project-");
        for byte in digest.iter().take(16) {
            use std::fmt::Write as _;
            write!(&mut tenant, "{byte:02x}").map_err(|_error| {
                AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
            })?;
        }
        Self::new(tenant, format!("uid-{}", metadata.uid()))
    }

    /// Resolves a Windows project tenant and owner principal while retaining the SID for pipe ACLs.
    #[cfg(windows)]
    pub fn from_project_root(project_root: &Path) -> Result<Self, AuthenticationError> {
        use std::os::windows::ffi::OsStrExt as _;

        if !project_root.is_absolute() {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let canonical = project_root.canonicalize().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
        if canonical != project_root {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let metadata = std::fs::symlink_metadata(project_root).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::LocalIdentityUnavailable,
            ));
        }
        let owner_sid = cigar_windows_ipc::file_owner_sid(project_root).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
        let mut tenant_hasher = Sha256::new();
        tenant_hasher.update(b"cigar.local-project-tenant.windows.v1\0");
        for unit in canonical.as_os_str().encode_wide() {
            tenant_hasher.update(unit.to_le_bytes());
        }
        let mut principal_hasher = Sha256::new();
        principal_hasher.update(b"cigar.local-project-owner.windows.v1\0");
        principal_hasher.update(owner_sid.as_bytes());
        let tenant = prefixed_digest("project-", &tenant_hasher.finalize())?;
        let principal = prefixed_digest("sid-", &principal_hasher.finalize())?;
        let mut identity = Self::new(tenant, principal)?;
        identity.windows_owner_sid = Some(Arc::from(owner_sid));
        Ok(identity)
    }

    /// Unsupported platforms require authenticated loopback transport instead of ambient IPC.
    #[cfg(not(any(unix, windows)))]
    pub fn from_project_root(_project_root: &Path) -> Result<Self, AuthenticationError> {
        Err(AuthenticationError::new(
            AuthenticationErrorCode::LocalIdentityUnavailable,
        ))
    }

    #[cfg(windows)]
    pub(crate) fn windows_owner_sid(&self) -> Option<&str> {
        self.windows_owner_sid.as_deref()
    }
}

#[cfg(windows)]
fn prefixed_digest(prefix: &str, digest: &[u8]) -> Result<String, AuthenticationError> {
    let mut value = String::from(prefix);
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::LocalIdentityUnavailable)
        })?;
    }
    Ok(value)
}

/// Identity extracted from a certificate after the TLS verifier accepted its chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClientCertificate {
    tenant: TenantId,
    principal: PrincipalId,
}

impl VerifiedClientCertificate {
    /// Records normalized SAN identity after transport-level certificate verification.
    pub fn from_verified_san(
        tenant: impl Into<String>,
        principal: impl Into<String>,
    ) -> Result<Self, AuthenticationError> {
        Ok(Self {
            tenant: TenantId::new(tenant)?,
            principal: PrincipalId::new(principal)?,
        })
    }
}

/// Bounded one-attempt JWKS refresh request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwksRefreshRequest {
    /// Exact pinned issuer.
    pub issuer: String,
    /// Maximum duration the provider may spend fetching.
    pub timeout: Duration,
    /// Maximum accepted response bytes.
    pub max_response_bytes: usize,
}

/// Owned asynchronous JWKS fetch. Construction must perform no I/O; the future owns the attempt.
pub type JwksRefreshFuture = Pin<
    Box<dyn Future<Output = Result<JwksRefreshResponse, AuthenticationError>> + Send + 'static>,
>;

/// Fresh JWKS response and exclusive cache expiry in Unix seconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwksRefreshResponse {
    /// Strict JSON document bytes.
    pub document: Vec<u8>,
    /// Exclusive cache expiry selected from HTTP and configured limits.
    pub valid_until_unix_seconds: i64,
}

/// Injectable network boundary for a bounded HTTPS JWKS fetch.
pub trait JwksRefresh: Send + Sync {
    /// Fetches the exact pinned issuer's key set within the supplied bounds.
    fn refresh(&self, request: JwksRefreshRequest) -> JwksRefreshFuture;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeySnapshot {
    keys: BTreeMap<String, [u8; 32]>,
    valid_until_unix_seconds: i64,
}

/// Strict EdDSA OIDC authenticator with issuer/audience pinning and bounded refresh.
pub struct OidcAuthenticator {
    settings: OidcSettings,
    refresh: Arc<dyn JwksRefresh>,
    snapshot: Mutex<Option<KeySnapshot>>,
    refresh_lock: tokio::sync::Mutex<()>,
    refresh_failure_until: Mutex<Option<tokio::time::Instant>>,
    refresh_disabled: AtomicBool,
}

impl OidcAuthenticator {
    /// Creates an empty-key authenticator; first use performs at most one refresh.
    #[must_use]
    pub fn new(settings: OidcSettings, refresh: Arc<dyn JwksRefresh>) -> Self {
        Self {
            settings,
            refresh,
            snapshot: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
            refresh_failure_until: Mutex::new(None),
            refresh_disabled: AtomicBool::new(false),
        }
    }

    /// Installs a strict bounded JWKS document, useful for startup prefetch.
    pub fn install_jwks(
        &self,
        document: &[u8],
        valid_until_unix_seconds: i64,
    ) -> Result<(), AuthenticationError> {
        let snapshot = parse_jwks(document, valid_until_unix_seconds)?;
        let mut guard = self.snapshot.lock().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })?;
        *guard = Some(snapshot);
        Ok(())
    }

    /// Verifies signature and all pinned semantic claims before returning identity.
    pub async fn authenticate(
        &self,
        token: &str,
        expected_tenant: Option<&TenantId>,
        certificate: Option<&VerifiedClientCertificate>,
        now_unix_seconds: i64,
    ) -> Result<AuthenticatedIdentity, AuthenticationError> {
        if token.len() > self.settings.max_token_bytes {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::InvalidCredential,
            ));
        }
        let mut segments = token.split('.');
        let header_text = segments.next().ok_or_else(invalid_credential)?;
        let claims_text = segments.next().ok_or_else(invalid_credential)?;
        let signature_text = segments.next().ok_or_else(invalid_credential)?;
        if segments.next().is_some()
            || header_text.is_empty()
            || claims_text.is_empty()
            || signature_text.is_empty()
        {
            return Err(invalid_credential());
        }
        let header_bytes = decode_segment(header_text, MAX_JWKS_BYTES)?;
        let header = parse_strict_json(&header_bytes).map_err(|_error| invalid_credential())?;
        let header = node_map(&header)?;
        let algorithm = required_text(header, "alg")?;
        let key_id = required_text(header, "kid")?;
        if algorithm != "EdDSA" || !valid_key_id(key_id) {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::SignatureRejected,
            ));
        }
        if optional_text(header, "typ")?.is_some_and(|token_type| token_type != "JWT") {
            return Err(invalid_credential());
        }

        let public_key = self.key_for(key_id, now_unix_seconds).await?;
        let signature_bytes = decode_segment(signature_text, 64)?;
        let signature: [u8; 64] = signature_bytes.try_into().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::SignatureRejected)
        })?;
        let signing_input = format!("{header_text}.{claims_text}");
        verify_ed25519(&public_key, signing_input.as_bytes(), &signature).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::SignatureRejected)
        })?;

        let claims_bytes = decode_segment(claims_text, self.settings.max_token_bytes)?;
        let claims = parse_strict_json(&claims_bytes).map_err(|_error| invalid_credential())?;
        let claims = node_map(&claims)?;
        let issuer = required_text(claims, "iss")?;
        let subject = required_text(claims, "sub")?;
        let tenant = required_text(claims, &self.settings.tenant_claim)?;
        if issuer != self.settings.issuer
            || !audience_contains(claims.get("aud"), &self.settings.audience)?
        {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::ScopeMismatch,
            ));
        }
        let skew = i64::try_from(self.settings.clock_skew_seconds)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::TemporalInvalid))?;
        let expires_at = required_i64(claims, "exp")?;
        let not_before = optional_i64(claims, "nbf")?;
        let issued_at = optional_i64(claims, "iat")?;
        if expires_at <= now_unix_seconds.saturating_sub(skew)
            || not_before.is_some_and(|value| value > now_unix_seconds.saturating_add(skew))
            || issued_at.is_some_and(|value| value > now_unix_seconds.saturating_add(skew))
        {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::TemporalInvalid,
            ));
        }
        let tenant = TenantId::new(tenant.to_owned())?;
        let principal = PrincipalId::new(subject.to_owned())?;
        if expected_tenant.is_some_and(|expected| expected != &tenant) {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::ScopeMismatch,
            ));
        }
        if certificate
            .is_some_and(|verified| verified.tenant != tenant || verified.principal != principal)
        {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::ScopeMismatch,
            ));
        }
        Ok(AuthenticatedIdentity::from_verified_credentials(
            tenant, principal,
        ))
    }

    fn fresh_key(
        &self,
        key_id: &str,
        now_unix_seconds: i64,
    ) -> Result<Option<[u8; 32]>, AuthenticationError> {
        let guard = self.snapshot.lock().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })?;
        if let Some(snapshot) = guard.as_ref()
            && now_unix_seconds < snapshot.valid_until_unix_seconds
        {
            return snapshot.keys.get(key_id).copied().map(Some).ok_or_else(|| {
                AuthenticationError::new(AuthenticationErrorCode::SignatureRejected)
            });
        }
        Ok(None)
    }

    fn refresh_is_blocked(&self) -> Result<bool, AuthenticationError> {
        if self.refresh_disabled.load(Ordering::Acquire) {
            return Ok(true);
        }
        self.refresh_failure_until
            .lock()
            .map(|failure_until| {
                failure_until.is_some_and(|deadline| tokio::time::Instant::now() < deadline)
            })
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable))
    }

    fn record_refresh_failure(&self, permanent: bool) -> Result<(), AuthenticationError> {
        if permanent {
            self.refresh_disabled.store(true, Ordering::Release);
        }
        let cooldown = Duration::from_millis(self.settings.jwks_refresh_timeout_ms);
        *self.refresh_failure_until.lock().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })? = Some(tokio::time::Instant::now() + cooldown);
        Ok(())
    }

    async fn key_for(
        &self,
        key_id: &str,
        now_unix_seconds: i64,
    ) -> Result<[u8; 32], AuthenticationError> {
        if let Some(key) = self.fresh_key(key_id, now_unix_seconds)? {
            return Ok(key);
        }
        if self.refresh_is_blocked()? {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
        let timeout = Duration::from_millis(self.settings.jwks_refresh_timeout_ms);
        let deadline = tokio::time::Instant::now() + timeout;
        let _refresh_guard = tokio::time::timeout_at(deadline, self.refresh_lock.lock())
            .await
            .map_err(|_elapsed| {
                AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
            })?;
        if let Some(key) = self.fresh_key(key_id, now_unix_seconds)? {
            return Ok(key);
        }
        if self.refresh_is_blocked()? {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
        let request = JwksRefreshRequest {
            issuer: self.settings.issuer.clone(),
            timeout,
            max_response_bytes: MAX_JWKS_BYTES,
        };
        let provider = Arc::clone(&self.refresh);
        let construction = tokio::task::spawn_blocking(move || provider.refresh(request));
        let refresh = match tokio::time::timeout_at(deadline, construction).await {
            Ok(Ok(refresh)) => refresh,
            Ok(Err(_)) | Err(_) => {
                self.record_refresh_failure(true)?;
                return Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ));
            }
        };
        let response = match tokio::time::timeout_at(deadline, refresh).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.record_refresh_failure(false)?;
                return Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ));
            }
            Err(_) => {
                self.record_refresh_failure(true)?;
                return Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ));
            }
        };
        if response.document.len() > MAX_JWKS_BYTES {
            self.record_refresh_failure(false)?;
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
        let configured_expiry = now_unix_seconds.saturating_add(
            i64::try_from(self.settings.jwks_max_age_seconds).map_err(|_error| {
                AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
            })?,
        );
        let expiry = response.valid_until_unix_seconds.min(configured_expiry);
        if expiry <= now_unix_seconds {
            self.record_refresh_failure(false)?;
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
        let snapshot = parse_jwks(&response.document, expiry).inspect_err(|_error| {
            let _ignored = self.record_refresh_failure(false);
        })?;
        let key = snapshot.keys.get(key_id).copied();
        let mut guard = self.snapshot.lock().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })?;
        *guard = Some(snapshot);
        *self.refresh_failure_until.lock().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })? = None;
        key.ok_or_else(|| AuthenticationError::new(AuthenticationErrorCode::SignatureRejected))
    }
}

impl fmt::Debug for OidcAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthenticator")
            .field("settings", &self.settings)
            .field("refresh", &"[HTTPS JWKS PROVIDER]")
            .field("snapshot", &"[REDACTED KEYS]")
            .finish()
    }
}

fn create_credential_file(path: &Path) -> Result<File, AuthenticationError> {
    #[cfg(windows)]
    {
        cigar_windows_ipc::create_owner_only_credential_file(path)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(path)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))
    }
}

fn validate_credential_file(path: &Path) -> Result<(), AuthenticationError> {
    drop(open_validated_credential_file(path)?);
    Ok(())
}

fn open_validated_credential_file(path: &Path) -> Result<File, AuthenticationError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AuthenticationError::new(
            AuthenticationErrorCode::UnsafeCredentialFile,
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::UnsafeCredentialFile,
            ));
        }
    }
    #[cfg(windows)]
    {
        cigar_windows_ipc::open_owner_only_credential_file(path).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::UnsafeCredentialFile)
        })
    }
    #[cfg(not(windows))]
    {
        File::open(path)
            .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::CredentialIo))
    }
}

fn validate_credential_parent(path: &Path) -> Result<(), AuthenticationError> {
    let parent = path
        .parent()
        .ok_or_else(|| AuthenticationError::new(AuthenticationErrorCode::UnsafeCredentialFile))?;
    let canonical = parent.canonicalize().map_err(|_error| {
        AuthenticationError::new(AuthenticationErrorCode::UnsafeCredentialFile)
    })?;
    if canonical != parent {
        return Err(AuthenticationError::new(
            AuthenticationErrorCode::UnsafeCredentialFile,
        ));
    }
    let metadata = std::fs::symlink_metadata(parent).map_err(|_error| {
        AuthenticationError::new(AuthenticationErrorCode::UnsafeCredentialFile)
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AuthenticationError::new(
            AuthenticationErrorCode::UnsafeCredentialFile,
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::UnsafeCredentialFile,
            ));
        }
    }
    Ok(())
}

fn parse_jwks(
    document: &[u8],
    valid_until_unix_seconds: i64,
) -> Result<KeySnapshot, AuthenticationError> {
    if document.is_empty() || document.len() > MAX_JWKS_BYTES {
        return Err(AuthenticationError::new(
            AuthenticationErrorCode::KeySetUnavailable,
        ));
    }
    let node = parse_strict_json(document)
        .map_err(|_error| AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable))?;
    let map = node_map(&node)?;
    let keys = match map.get("keys") {
        Some(CanonicalNode::Array(keys)) if !keys.is_empty() && keys.len() <= MAX_JWKS_KEYS => keys,
        _ => {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
    };
    let mut parsed = BTreeMap::new();
    for key in keys {
        let key = node_map(key)?;
        let key_id = required_text(key, "kid")?;
        let key_type = required_text(key, "kty")?;
        let curve = required_text(key, "crv")?;
        let algorithm = required_text(key, "alg")?;
        let use_kind = required_text(key, "use")?;
        let encoded = required_text(key, "x")?;
        if !valid_key_id(key_id)
            || key_type != "OKP"
            || curve != "Ed25519"
            || algorithm != "EdDSA"
            || use_kind != "sig"
            || key.contains_key("d")
        {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_error| {
            AuthenticationError::new(AuthenticationErrorCode::KeySetUnavailable)
        })?;
        if parsed.insert(key_id.to_owned(), public_key).is_some() {
            return Err(AuthenticationError::new(
                AuthenticationErrorCode::KeySetUnavailable,
            ));
        }
    }
    Ok(KeySnapshot {
        keys: parsed,
        valid_until_unix_seconds,
    })
}

fn node_map(node: &CanonicalNode) -> Result<&BTreeMap<String, CanonicalNode>, AuthenticationError> {
    match node {
        CanonicalNode::Map(map) => Ok(map),
        _ => Err(invalid_credential()),
    }
}

fn required_text<'a>(
    map: &'a BTreeMap<String, CanonicalNode>,
    name: &str,
) -> Result<&'a str, AuthenticationError> {
    match map.get(name) {
        Some(CanonicalNode::Text(value))
            if !value.is_empty()
                && value.len() <= MAX_CLAIM_TEXT_BYTES
                && !value.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Ok(value)
        }
        _ => Err(invalid_credential()),
    }
}

fn optional_text<'a>(
    map: &'a BTreeMap<String, CanonicalNode>,
    name: &str,
) -> Result<Option<&'a str>, AuthenticationError> {
    map.get(name)
        .map(|_node| required_text(map, name))
        .transpose()
}

fn required_i64(
    map: &BTreeMap<String, CanonicalNode>,
    name: &str,
) -> Result<i64, AuthenticationError> {
    optional_i64(map, name)?.ok_or_else(invalid_credential)
}

fn optional_i64(
    map: &BTreeMap<String, CanonicalNode>,
    name: &str,
) -> Result<Option<i64>, AuthenticationError> {
    match map.get(name) {
        None => Ok(None),
        Some(CanonicalNode::Unsigned(value)) => i64::try_from(*value)
            .map(Some)
            .map_err(|_error| invalid_credential()),
        Some(CanonicalNode::Negative(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_credential()),
    }
}

fn audience_contains(
    node: Option<&CanonicalNode>,
    expected: &str,
) -> Result<bool, AuthenticationError> {
    match node {
        Some(CanonicalNode::Text(value)) => Ok(value == expected),
        Some(CanonicalNode::Array(values)) if values.len() <= MAX_AUDIENCES => {
            let mut matched = false;
            for value in values {
                match value {
                    CanonicalNode::Text(value) if value.len() <= MAX_CLAIM_TEXT_BYTES => {
                        matched |= value == expected;
                    }
                    _ => return Err(invalid_credential()),
                }
            }
            Ok(matched)
        }
        _ => Err(invalid_credential()),
    }
}

fn decode_segment(segment: &str, max_bytes: usize) -> Result<Vec<u8>, AuthenticationError> {
    if segment.is_empty() || segment.len() > max_bytes.saturating_mul(2) {
        return Err(invalid_credential());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_error| invalid_credential())?;
    if bytes.len() > max_bytes {
        Err(invalid_credential())
    } else {
        Ok(bytes)
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn invalid_credential() -> AuthenticationError {
    AuthenticationError::new(AuthenticationErrorCode::InvalidCredential)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticationError, AuthenticationErrorCode, JwksRefresh, JwksRefreshFuture,
        JwksRefreshRequest, LocalBearerToken, LocalIdentity, OidcAuthenticator,
        VerifiedClientCertificate,
    };
    use crate::config::OidcSettings;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use cigar_api::TenantId;
    use cigar_crypto::{ed25519_public_key, generate_ed25519_secret, sign_ed25519};
    use serde_json::json;
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    struct NeverRefresh;

    impl JwksRefresh for NeverRefresh {
        fn refresh(&self, _request: JwksRefreshRequest) -> JwksRefreshFuture {
            Box::pin(async {
                Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ))
            })
        }
    }

    struct HangingRefresh {
        calls: Arc<AtomicUsize>,
    }

    impl JwksRefresh for HangingRefresh {
        fn refresh(&self, request: JwksRefreshRequest) -> JwksRefreshFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.issuer, "https://issuer.example");
            assert!(request.timeout <= Duration::from_millis(100));
            assert!(request.max_response_bytes > 0);
            Box::pin(pending())
        }
    }

    struct FailingRefresh {
        calls: Arc<AtomicUsize>,
    }

    struct BlockingConstructorRefresh {
        calls: Arc<AtomicUsize>,
    }

    impl JwksRefresh for BlockingConstructorRefresh {
        fn refresh(&self, _request: JwksRefreshRequest) -> JwksRefreshFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
            Box::pin(async {
                Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ))
            })
        }
    }

    impl JwksRefresh for FailingRefresh {
        fn refresh(&self, _request: JwksRefreshRequest) -> JwksRefreshFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AuthenticationError::new(
                    AuthenticationErrorCode::KeySetUnavailable,
                ))
            })
        }
    }

    struct DelayedRefresh {
        calls: Arc<AtomicUsize>,
        document: Vec<u8>,
        valid_until: i64,
    }

    impl JwksRefresh for DelayedRefresh {
        fn refresh(&self, _request: JwksRefreshRequest) -> JwksRefreshFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = super::JwksRefreshResponse {
                document: self.document.clone(),
                valid_until_unix_seconds: self.valid_until,
            };
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(response)
            })
        }
    }

    fn settings() -> OidcSettings {
        OidcSettings {
            issuer: "https://issuer.example".to_owned(),
            audience: "cigar-api".to_owned(),
            tenant_claim: "tenant".to_owned(),
            jwks_max_age_seconds: 300,
            jwks_refresh_timeout_ms: 100,
            clock_skew_seconds: 30,
            max_token_bytes: 4_096,
        }
    }

    fn token(
        secret: &cigar_crypto::SecretBytes,
        header: serde_json::Value,
        claims: serde_json::Value,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header}.{claims}");
        let signature = sign_ed25519(secret, signing_input.as_bytes())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn jwks(public: [u8; 32]) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&json!({"keys": [{
            "alg": "EdDSA", "crv": "Ed25519", "kid": "key-1", "kty": "OKP",
            "use": "sig", "x": URL_SAFE_NO_PAD.encode(public)
        }]}))
    }

    fn valid_claims() -> serde_json::Value {
        json!({
            "iss": "https://issuer.example", "aud": "cigar-api",
            "sub": "service-a", "tenant": "tenant-a", "iat": 990,
            "nbf": 990, "exp": 1_100
        })
    }

    #[test]
    fn local_token_file_is_restricted_and_exact() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("token");
        let created = LocalBearerToken::create_file(&path)?;
        let loaded = LocalBearerToken::read_file(&path)?;
        let identity = LocalIdentity::new("tenant-local", "user-local")?;
        let header = format!("Bearer {}", std::fs::read_to_string(&path)?);
        assert_eq!(
            created.authenticate(&header, &identity)?,
            loaded.authenticate(&header, &identity)?
        );
        assert!(created.authenticate("Bearer invalid", &identity).is_err());
        assert!(!format!("{created:?}").contains(&std::fs::read_to_string(path)?));
        Ok(())
    }

    #[tokio::test]
    async fn pinned_oidc_accepts_valid_eddsa_and_rejects_attacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let public = ed25519_public_key(&secret)?;
        let jwks = serde_json::to_vec(&json!({"keys": [{
            "alg": "EdDSA", "crv": "Ed25519", "kid": "key-1", "kty": "OKP",
            "use": "sig", "x": URL_SAFE_NO_PAD.encode(public)
        }]}))?;
        let authenticator = OidcAuthenticator::new(settings(), Arc::new(NeverRefresh));
        authenticator.install_jwks(&jwks, 2_000)?;
        let claims = json!({
            "iss": "https://issuer.example", "aud": ["other", "cigar-api"],
            "sub": "service-a", "tenant": "tenant-a", "iat": 990,
            "nbf": 990, "exp": 1_100
        });
        let valid = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1", "typ": "JWT"}),
            claims.clone(),
        )?;
        let tenant = TenantId::new("tenant-a")?;
        let certificate = VerifiedClientCertificate::from_verified_san("tenant-a", "service-a")?;
        let identity = authenticator
            .authenticate(&valid, Some(&tenant), Some(&certificate), 1_000)
            .await?;
        assert_eq!(identity.tenant(), &tenant);

        let none_algorithm = token(
            &secret,
            json!({"alg": "none", "kid": "key-1", "typ": "JWT"}),
            claims.clone(),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&none_algorithm, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::SignatureRejected)
        );

        let wrong_audience = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            json!({"iss": "https://issuer.example", "aud": "wrong", "sub": "service-a", "tenant": "tenant-a", "exp": 1100}),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&wrong_audience, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::ScopeMismatch)
        );

        let missing_audience = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            json!({"iss": "https://issuer.example", "sub": "service-a", "tenant": "tenant-a", "exp": 1100}),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&missing_audience, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::InvalidCredential)
        );

        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg": "EdDSA", "kid": "key-1"}),
        )?);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let unsigned = format!("{header}.{claims}.");
        assert_eq!(
            authenticator
                .authenticate(&unsigned, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::InvalidCredential)
        );

        let expired = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            json!({"iss": "https://issuer.example", "aud": "cigar-api", "sub": "service-a", "tenant": "tenant-a", "exp": 900}),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&expired, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::TemporalInvalid)
        );
        Ok(())
    }

    #[tokio::test]
    async fn oidc_attack_matrix_rejects_expired_keys_and_identity_binding_confusion()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let public = ed25519_public_key(&secret)?;
        let document = jwks(public)?;
        let authenticator = OidcAuthenticator::new(settings(), Arc::new(NeverRefresh));
        authenticator.install_jwks(&document, 2_000)?;
        let valid = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1", "typ": "JWT"}),
            valid_claims(),
        )?;

        let wrong_issuer = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            json!({
                "iss": "https://attacker.example", "aud": "cigar-api",
                "sub": "service-a", "tenant": "tenant-a", "exp": 1_100
            }),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&wrong_issuer, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::ScopeMismatch)
        );

        let wrong_tenant = TenantId::new("tenant-b")?;
        assert_eq!(
            authenticator
                .authenticate(&valid, Some(&wrong_tenant), None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::ScopeMismatch)
        );

        let wrong_certificate =
            VerifiedClientCertificate::from_verified_san("tenant-a", "service-b")?;
        assert_eq!(
            authenticator
                .authenticate(&valid, None, Some(&wrong_certificate), 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::ScopeMismatch)
        );

        let future = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            json!({
                "iss": "https://issuer.example", "aud": "cigar-api",
                "sub": "service-a", "tenant": "tenant-a", "iat": 1_100,
                "nbf": 1_100, "exp": 1_200
            }),
        )?;
        assert_eq!(
            authenticator
                .authenticate(&future, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::TemporalInvalid)
        );

        let expired_keys = OidcAuthenticator::new(settings(), Arc::new(NeverRefresh));
        expired_keys.install_jwks(&document, 1_000)?;
        assert_eq!(
            expired_keys
                .authenticate(&valid, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::KeySetUnavailable)
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_claim_and_oversized_token_fail_before_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let public = ed25519_public_key(&secret)?;
        let jwks = serde_json::to_vec(&json!({"keys": [{
            "alg": "EdDSA", "crv": "Ed25519", "kid": "key-1", "kty": "OKP",
            "use": "sig", "x": URL_SAFE_NO_PAD.encode(public)
        }]}))?;
        let authenticator = OidcAuthenticator::new(settings(), Arc::new(NeverRefresh));
        authenticator.install_jwks(&jwks, 2_000)?;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key-1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","aud":"cigar-api","sub":"one","sub":"two","tenant":"tenant-a","exp":1100}"#);
        let input = format!("{header}.{claims}");
        let signature = sign_ed25519(&secret, input.as_bytes())?;
        let duplicate = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            authenticator
                .authenticate(&duplicate, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::InvalidCredential)
        );
        let oversized = "x".repeat(4_097);
        assert!(
            authenticator
                .authenticate(&oversized, None, None, 1_000)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn hanging_refresh_is_cancelled_at_the_configured_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let mut bounded = settings();
        bounded.jwks_refresh_timeout_ms = 25;
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = OidcAuthenticator::new(
            bounded,
            Arc::new(HangingRefresh {
                calls: Arc::clone(&calls),
            }),
        );
        let candidate = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1", "typ": "JWT"}),
            valid_claims(),
        )?;
        let started = Instant::now();
        let failure = authenticator
            .authenticate(&candidate, None, None, 1_000)
            .await
            .err()
            .ok_or("hanging refresh unexpectedly authenticated")?;
        assert_eq!(failure.code(), AuthenticationErrorCode::KeySetUnavailable);
        assert!(started.elapsed() < Duration::from_millis(250));
        // The end-to-end deadline includes blocking-pool queue time, so a loaded runtime may
        // expire before provider construction begins. No second attempt may be admitted.
        let attempts_after_timeout = calls.load(Ordering::SeqCst);
        assert!(attempts_after_timeout <= 1);
        assert!(
            authenticator
                .authenticate(&candidate, None, None, 1_000)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), attempts_after_timeout);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_refresh_constructor_times_out_once_and_opens_permanent_circuit()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let mut bounded = settings();
        bounded.jwks_refresh_timeout_ms = 20;
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = OidcAuthenticator::new(
            bounded,
            Arc::new(BlockingConstructorRefresh {
                calls: Arc::clone(&calls),
            }),
        );
        let candidate = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            valid_claims(),
        )?;
        let started = Instant::now();
        assert_eq!(
            authenticator
                .authenticate(&candidate, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::KeySetUnavailable)
        );
        assert!(started.elapsed() < Duration::from_millis(75));
        // A constructor still queued when the deadline expires is the one admitted attempt; the
        // permanent circuit must reject a second attempt without invoking the provider again.
        let attempts_after_timeout = calls.load(Ordering::SeqCst);
        assert!(attempts_after_timeout <= 1);
        assert_eq!(
            authenticator
                .authenticate(&candidate, None, None, 1_000)
                .await
                .err()
                .map(|error| error.code()),
            Some(AuthenticationErrorCode::KeySetUnavailable)
        );
        assert_eq!(calls.load(Ordering::SeqCst), attempts_after_timeout);
        Ok(())
    }

    #[tokio::test]
    async fn expired_keyset_refresh_failure_enters_single_attempt_cooldown()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let public = ed25519_public_key(&secret)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = OidcAuthenticator::new(
            settings(),
            Arc::new(FailingRefresh {
                calls: Arc::clone(&calls),
            }),
        );
        authenticator.install_jwks(&jwks(public)?, 999)?;
        let candidate = token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            valid_claims(),
        )?;
        for _attempt in 0..2 {
            assert_eq!(
                authenticator
                    .authenticate(&candidate, None, None, 1_000)
                    .await
                    .err()
                    .map(|error| error.code()),
                Some(AuthenticationErrorCode::KeySetUnavailable)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_stale_key_requests_share_exactly_one_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = generate_ed25519_secret()?;
        let public = ed25519_public_key(&secret)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = Arc::new(OidcAuthenticator::new(
            settings(),
            Arc::new(DelayedRefresh {
                calls: Arc::clone(&calls),
                document: jwks(public)?,
                valid_until: 2_000,
            }),
        ));
        let candidate = Arc::new(token(
            &secret,
            json!({"alg": "EdDSA", "kid": "key-1"}),
            valid_claims(),
        )?);
        let mut requests = Vec::new();
        for _index in 0..16 {
            let authenticator = Arc::clone(&authenticator);
            let candidate = Arc::clone(&candidate);
            requests.push(tokio::spawn(async move {
                authenticator
                    .authenticate(candidate.as_str(), None, None, 1_000)
                    .await
            }));
        }
        for request in requests {
            let identity = request.await??;
            assert_eq!(identity.tenant(), &TenantId::new("tenant-a")?);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn local_project_identity_uses_canonical_root_owner_and_rejects_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let first = LocalIdentity::from_project_root(&root)?;
        let second = LocalIdentity::from_project_root(&root)?;
        assert_eq!(first, second);
        let authenticated = first.authenticated();
        assert!(authenticated.tenant().as_str().starts_with("project-"));
        assert!(authenticated.principal().as_str().starts_with("uid-"));

        let alias = root
            .parent()
            .ok_or("root parent missing")?
            .join(format!("cigar-project-alias-{}", std::process::id()));
        symlink(&root, &alias)?;
        let result = LocalIdentity::from_project_root(&alias);
        std::fs::remove_file(alias)?;
        assert_eq!(
            result.err().map(|error| error.code()),
            Some(AuthenticationErrorCode::LocalIdentityUnavailable)
        );
        Ok(())
    }
}
