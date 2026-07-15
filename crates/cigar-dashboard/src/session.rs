//! One-time bootstrap and bounded local browser sessions.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 32;
const MAX_TOKEN_TEXT_BYTES: usize = 64;
const MIN_SESSION_TTL: Duration = Duration::from_secs(60);
const MAX_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SESSIONS: usize = 128;

type HmacSha256 = Hmac<Sha256>;

/// Stable content-free bootstrap/session failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// Operating-system secure randomness was unavailable.
    RandomUnavailable,
    /// A token was malformed, expired, unknown, or already consumed.
    Unauthorized,
    /// The supplied CSRF proof did not bind the current session.
    CsrfRejected,
    /// Session duration or capacity was outside its hard bound.
    InvalidConfiguration,
    /// The bounded session store was unavailable or full.
    StoreUnavailable,
    /// The owner-only bootstrap file could not be safely created and flushed.
    BootstrapFileUnavailable,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomUnavailable => "secure randomness is unavailable",
            Self::Unauthorized => "dashboard authentication is required",
            Self::CsrfRejected => "dashboard CSRF proof was rejected",
            Self::InvalidConfiguration => "dashboard session configuration is invalid",
            Self::StoreUnavailable => "dashboard session store is unavailable",
            Self::BootstrapFileUnavailable => "dashboard bootstrap file is unavailable",
        })
    }
}

impl std::error::Error for SessionError {}

/// One-time bootstrap verifier that retains no plaintext bootstrap secret.
pub struct BootstrapAuthority {
    key: Zeroizing<[u8; TOKEN_BYTES]>,
    expected_mac: [u8; TOKEN_BYTES],
    consumed: AtomicBool,
}

impl BootstrapAuthority {
    /// Generates a new one-time authority plus its copy-safe bootstrap token.
    pub fn generate() -> Result<(Self, Zeroizing<String>), SessionError> {
        let key = random_bytes()?;
        let token_bytes = random_bytes()?;
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(*token_bytes));
        let expected_mac = token_mac(&key, &token_bytes)?;
        Ok((
            Self {
                key,
                expected_mac,
                consumed: AtomicBool::new(false),
            },
            token,
        ))
    }

    fn consume(&self, presented: &str) -> Result<(), SessionError> {
        if self.consumed.load(Ordering::Acquire) {
            return Err(SessionError::Unauthorized);
        }
        let token = decode_token(presented)?;
        let mut verifier = new_mac(&self.key)?;
        verifier.update(token.as_slice());
        verifier
            .verify_slice(&self.expected_mac)
            .map_err(|_error| SessionError::Unauthorized)?;
        self.consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_prior| SessionError::Unauthorized)?;
        Ok(())
    }
}

impl fmt::Debug for BootstrapAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapAuthority")
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Newly issued browser credentials. Debug output never exposes token material.
pub struct SessionCredentials {
    session_token: Zeroizing<String>,
    csrf_token: Zeroizing<String>,
}

impl SessionCredentials {
    /// Returns the opaque value used only in the dashboard session cookie.
    #[must_use]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// Returns the session-bound CSRF value returned once to browser memory.
    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentials")
            .field("session_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy)]
struct SessionRecord {
    csrf_mac: [u8; TOKEN_BYTES],
    expires_at: Instant,
}

#[derive(Default)]
struct SessionState {
    sessions: BTreeMap<[u8; TOKEN_BYTES], SessionRecord>,
}

/// Bounded in-memory dashboard session manager.
pub struct SessionManager {
    bootstrap: BootstrapAuthority,
    key: Zeroizing<[u8; TOKEN_BYTES]>,
    state: Mutex<SessionState>,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionManager {
    /// Creates a bounded manager around one generated bootstrap authority.
    pub fn new(
        bootstrap: BootstrapAuthority,
        ttl: Duration,
        max_sessions: usize,
    ) -> Result<Self, SessionError> {
        if !(MIN_SESSION_TTL..=MAX_SESSION_TTL).contains(&ttl)
            || !(1..=MAX_SESSIONS).contains(&max_sessions)
        {
            return Err(SessionError::InvalidConfiguration);
        }
        Ok(Self {
            bootstrap,
            key: random_bytes()?,
            state: Mutex::new(SessionState::default()),
            ttl,
            max_sessions,
        })
    }

    /// Consumes the one-time bootstrap token and creates one browser session.
    pub fn exchange(&self, bootstrap_token: &str) -> Result<SessionCredentials, SessionError> {
        self.bootstrap.consume(bootstrap_token)?;
        let session_bytes = random_bytes()?;
        let csrf_bytes = random_bytes()?;
        let session_mac = domain_mac(&self.key, b"session", &session_bytes)?;
        let csrf_mac = domain_mac(&self.key, b"csrf", &csrf_bytes)?;
        let expires_at = Instant::now()
            .checked_add(self.ttl)
            .ok_or(SessionError::InvalidConfiguration)?;
        let mut state = self.lock_state()?;
        prune_expired(&mut state, Instant::now());
        if state.sessions.len() >= self.max_sessions {
            return Err(SessionError::StoreUnavailable);
        }
        state.sessions.insert(
            session_mac,
            SessionRecord {
                csrf_mac,
                expires_at,
            },
        );
        Ok(SessionCredentials {
            session_token: Zeroizing::new(URL_SAFE_NO_PAD.encode(*session_bytes)),
            csrf_token: Zeroizing::new(URL_SAFE_NO_PAD.encode(*csrf_bytes)),
        })
    }

    /// Validates one session and, when supplied, its session-bound CSRF token.
    pub fn authorize(
        &self,
        session_token: &str,
        csrf_token: Option<&str>,
    ) -> Result<(), SessionError> {
        let session_bytes = decode_token(session_token)?;
        let session_mac = domain_mac(&self.key, b"session", &session_bytes)?;
        let mut state = self.lock_state()?;
        let now = Instant::now();
        prune_expired(&mut state, now);
        let record = state
            .sessions
            .get(&session_mac)
            .copied()
            .ok_or(SessionError::Unauthorized)?;
        if record.expires_at <= now {
            state.sessions.remove(&session_mac);
            return Err(SessionError::Unauthorized);
        }
        if let Some(presented) = csrf_token {
            let csrf_bytes =
                decode_token(presented).map_err(|_error| SessionError::CsrfRejected)?;
            let mut verifier = new_mac(&self.key)?;
            verifier.update(b"csrf");
            verifier.update(&[0]);
            verifier.update(csrf_bytes.as_slice());
            verifier
                .verify_slice(&record.csrf_mac)
                .map_err(|_error| SessionError::CsrfRejected)?;
        }
        Ok(())
    }

    /// Revokes one session. Repeated or unknown revocation remains content-free.
    pub fn revoke(&self, session_token: &str) -> Result<(), SessionError> {
        let session_bytes = decode_token(session_token)?;
        let session_mac = domain_mac(&self.key, b"session", &session_bytes)?;
        self.lock_state()?.sessions.remove(&session_mac);
        Ok(())
    }

    /// Rotates the CSRF proof for an already authenticated same-origin browser session.
    ///
    /// Only its keyed digest remains in memory. This supports browser reload without persisting
    /// the prior proof in local/session storage.
    pub fn rotate_csrf(&self, session_token: &str) -> Result<Zeroizing<String>, SessionError> {
        let session_bytes = decode_token(session_token)?;
        let session_mac = domain_mac(&self.key, b"session", &session_bytes)?;
        let csrf_bytes = random_bytes()?;
        let csrf_mac = domain_mac(&self.key, b"csrf", &csrf_bytes)?;
        let mut state = self.lock_state()?;
        let now = Instant::now();
        prune_expired(&mut state, now);
        let record = state
            .sessions
            .get_mut(&session_mac)
            .ok_or(SessionError::Unauthorized)?;
        if record.expires_at <= now {
            state.sessions.remove(&session_mac);
            return Err(SessionError::Unauthorized);
        }
        record.csrf_mac = csrf_mac;
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(*csrf_bytes)))
    }

    /// Returns the current bounded session count for content-safe diagnostics.
    pub fn active_session_count(&self) -> Result<usize, SessionError> {
        let mut state = self.lock_state()?;
        prune_expired(&mut state, Instant::now());
        Ok(state.sessions.len())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, SessionState>, SessionError> {
        self.state
            .lock()
            .map_err(|_poisoned| SessionError::StoreUnavailable)
    }
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionManager")
            .field("bootstrap", &self.bootstrap)
            .field("ttl", &self.ttl)
            .field("max_sessions", &self.max_sessions)
            .finish_non_exhaustive()
    }
}

/// Writes the one-time bootstrap token to a create-new owner-only file and flushes it.
pub fn write_bootstrap_file(path: &Path, token: &str) -> Result<(), SessionError> {
    if !path.is_absolute() || token.len() > MAX_TOKEN_TEXT_BYTES || decode_token(token).is_err() {
        return Err(SessionError::BootstrapFileUnavailable);
    }
    let parent = path
        .parent()
        .ok_or(SessionError::BootstrapFileUnavailable)?;
    let parent_before =
        fs::symlink_metadata(parent).map_err(|_error| SessionError::BootstrapFileUnavailable)?;
    if !private_runtime_directory(&parent_before) {
        return Err(SessionError::BootstrapFileUnavailable);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_error| SessionError::BootstrapFileUnavailable)?;
    file.write_all(token.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_error| SessionError::BootstrapFileUnavailable)?;
    let parent_after =
        fs::symlink_metadata(parent).map_err(|_error| SessionError::BootstrapFileUnavailable)?;
    if !private_runtime_directory(&parent_after) || !same_directory(&parent_before, &parent_after) {
        return Err(SessionError::BootstrapFileUnavailable);
    }
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| SessionError::BootstrapFileUnavailable)
}

#[cfg(unix)]
fn private_runtime_directory(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o777 == 0o700
}

#[cfg(not(unix))]
fn private_runtime_directory(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_directory(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_directory(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn random_bytes() -> Result<Zeroizing<[u8; TOKEN_BYTES]>, SessionError> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    getrandom::fill(&mut *bytes).map_err(|_error| SessionError::RandomUnavailable)?;
    Ok(bytes)
}

fn decode_token(value: &str) -> Result<Zeroizing<[u8; TOKEN_BYTES]>, SessionError> {
    if value.is_empty() || value.len() > MAX_TOKEN_TEXT_BYTES {
        return Err(SessionError::Unauthorized);
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_error| SessionError::Unauthorized)?,
    );
    let bytes: [u8; TOKEN_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_error| SessionError::Unauthorized)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(SessionError::Unauthorized);
    }
    Ok(Zeroizing::new(bytes))
}

fn token_mac(
    key: &[u8; TOKEN_BYTES],
    token: &[u8; TOKEN_BYTES],
) -> Result<[u8; TOKEN_BYTES], SessionError> {
    let mut mac = new_mac(key)?;
    mac.update(token);
    Ok(mac.finalize().into_bytes().into())
}

fn domain_mac(
    key: &[u8; TOKEN_BYTES],
    domain: &[u8],
    token: &[u8; TOKEN_BYTES],
) -> Result<[u8; TOKEN_BYTES], SessionError> {
    let mut mac = new_mac(key)?;
    mac.update(domain);
    mac.update(&[0]);
    mac.update(token);
    Ok(mac.finalize().into_bytes().into())
}

fn new_mac(key: &[u8; TOKEN_BYTES]) -> Result<HmacSha256, SessionError> {
    <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_error| SessionError::RandomUnavailable)
}

fn prune_expired(state: &mut SessionState, now: Instant) {
    state
        .sessions
        .retain(|_identity, record| record.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::{
        BootstrapAuthority, SessionError, SessionManager, decode_token, write_bootstrap_file,
    };
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    #[test]
    fn bootstrap_is_one_time_and_session_requires_bound_csrf()
    -> Result<(), Box<dyn std::error::Error>> {
        let (bootstrap, token) = BootstrapAuthority::generate()?;
        let manager = SessionManager::new(bootstrap, Duration::from_secs(300), 4)?;
        let credentials = manager.exchange(&token)?;
        manager.authorize(credentials.session_token(), None)?;
        manager.authorize(credentials.session_token(), Some(credentials.csrf_token()))?;
        assert_eq!(manager.active_session_count()?, 1);
        assert!(matches!(
            manager.exchange(&token),
            Err(SessionError::Unauthorized)
        ));
        assert_eq!(
            manager.authorize(credentials.session_token(), Some("wrong")),
            Err(SessionError::CsrfRejected)
        );
        manager.revoke(credentials.session_token())?;
        assert_eq!(
            manager.authorize(credentials.session_token(), None),
            Err(SessionError::Unauthorized)
        );
        Ok(())
    }

    #[test]
    fn noncanonical_and_wrong_length_tokens_are_rejected() {
        assert!(decode_token("").is_err());
        assert!(decode_token("not+base64").is_err());
        assert!(decode_token("AA").is_err());
    }

    #[test]
    fn bootstrap_file_is_create_new_and_owner_only() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("bootstrap.token");
        let (_authority, token) = BootstrapAuthority::generate()?;
        write_bootstrap_file(&path, &token)?;
        let contents = fs::read_to_string(&path)?;
        assert_eq!(contents.trim(), token.as_str());
        assert_eq!(
            write_bootstrap_file(&path, &token),
            Err(SessionError::BootstrapFileUnavailable)
        );
        #[cfg(unix)]
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn configuration_bounds_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (bootstrap, _token) = BootstrapAuthority::generate()?;
        assert!(matches!(
            SessionManager::new(bootstrap, Duration::from_secs(1), 1),
            Err(SessionError::InvalidConfiguration)
        ));
        Ok(())
    }
}
