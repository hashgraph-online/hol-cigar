//! Secure listener planning, local IPC preparation, and shared TLS material.

use crate::{
    DaemonConfig, DaemonError, DaemonErrorCode, DeploymentMode, SharedTransportSecurity, TlsFiles,
};
use axum_server::tls_rustls::RustlsConfig;
use cigar_api::VerifiedClientIdentity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

const MAX_TLS_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PENDING_TLS_HANDSHAKES: usize = 128;
#[cfg(not(test))]
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(100);

/// Platform-neutral local IPC endpoint selected from validated daemon configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalIpcEndpoint {
    /// Permission-restricted filesystem Unix-domain socket.
    UnixSocket(PathBuf),
    /// Windows named pipe with a server-owned access control list.
    WindowsNamedPipe(String),
}

impl LocalIpcEndpoint {
    /// Resolves the current platform's local endpoint without weakening to public TCP.
    pub fn for_config(config: &DaemonConfig) -> Result<Option<Self>, DaemonError> {
        if config.mode != DeploymentMode::Local {
            return Ok(None);
        }
        #[cfg(unix)]
        {
            if config.windows_named_pipe.is_some() {
                return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
            }
            Ok(config.unix_socket.clone().map(Self::UnixSocket))
        }
        #[cfg(windows)]
        {
            if config.unix_socket.is_some() {
                return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
            }
            Ok(config
                .windows_named_pipe
                .clone()
                .map(Self::WindowsNamedPipe))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = config;
            Ok(None)
        }
    }

    /// Validates the closed Windows named-pipe namespace used by the daemon abstraction.
    #[must_use]
    pub fn is_safe_windows_pipe_name(value: &str) -> bool {
        let Some(suffix) = value.strip_prefix(r"\\.\pipe\cigar-") else {
            return false;
        };
        !suffix.is_empty()
            && value.len() <= 256
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    }
}

/// Exact listener set selected from a validated configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerPlan {
    /// Local IPC listener, when configured.
    pub local_ipc: Option<LocalIpcEndpoint>,
    /// HTTP/JSON and SSE TCP listener.
    pub http: Option<SocketAddr>,
    /// Tonic gRPC TCP listener.
    pub grpc: Option<SocketAddr>,
    /// Whether every TCP listener must terminate TLS.
    pub tls_required: bool,
}

impl ListenerPlan {
    /// Revalidates exposure invariants and returns an exact listener plan.
    pub fn from_config(config: &DaemonConfig) -> Result<Self, DaemonError> {
        config
            .validate()
            .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
        Ok(Self {
            local_ipc: LocalIpcEndpoint::for_config(config)?,
            http: config.http_listen,
            grpc: config.grpc_listen,
            tls_required: config.mode == DeploymentMode::Shared,
        })
    }
}

/// Guard that removes only the Unix socket created by this process.
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl UnixSocketGuard {
    /// Binds a new socket without unlinking an existing filesystem object.
    pub fn bind(config: &DaemonConfig) -> Result<(tokio::net::UnixListener, Self), DaemonError> {
        let path = config
            .unix_socket
            .as_ref()
            .ok_or_else(|| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
        prepare_runtime_directory(&config.runtime_directory)?;
        match std::fs::symlink_metadata(path) {
            Ok(_metadata) => {
                return Err(DaemonError::new(DaemonErrorCode::UnsafeRuntimePath));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_error) => {
                return Err(DaemonError::new(DaemonErrorCode::UnsafeRuntimePath));
            }
        }
        let listener = tokio::net::UnixListener::bind(path)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_error| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
        use std::os::unix::fs::FileTypeExt as _;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
        {
            let _ignored = std::fs::remove_file(path);
            return Err(DaemonError::new(DaemonErrorCode::UnsafeRuntimePath));
        }
        Ok((
            listener,
            Self {
                path: path.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        ))
    }
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        use std::os::unix::fs::FileTypeExt as _;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ignored = std::fs::remove_file(&self.path);
        }
    }
}

/// Axum listener over owner-ACL-restricted, local-only Windows named-pipe instances.
#[cfg(windows)]
pub struct WindowsPipeListener {
    pipe_name: String,
    owner_sid: Arc<str>,
    pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

#[cfg(windows)]
impl WindowsPipeListener {
    /// Creates the first exclusive instance using the audited platform ACL adapter.
    pub fn bind(pipe_name: String, owner_sid: Arc<str>) -> Result<Self, DaemonError> {
        if !LocalIpcEndpoint::is_safe_windows_pipe_name(&pipe_name) || owner_sid.is_empty() {
            return Err(DaemonError::new(DaemonErrorCode::UnsafeRuntimePath));
        }
        let pending = cigar_windows_ipc::create_user_only_named_pipe(&pipe_name, &owner_sid, true)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
        Ok(Self {
            pipe_name,
            owner_sid,
            pending: Some(pending),
        })
    }

    fn next_instance(&self) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        cigar_windows_ipc::create_user_only_named_pipe(&self.pipe_name, &self.owner_sid, false)
    }
}

#[cfg(windows)]
impl axum::serve::Listener for WindowsPipeListener {
    type Io = tokio::net::windows::named_pipe::NamedPipeServer;
    type Addr = String;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let mut current = match self.pending.take() {
                Some(current) => current,
                None => match self.next_instance() {
                    Ok(next) => next,
                    Err(_error) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            if current.connect().await.is_err() {
                continue;
            }
            loop {
                match self.next_instance() {
                    Ok(next) => {
                        self.pending = Some(next);
                        return (current, self.pipe_name.clone());
                    }
                    Err(_error) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.pipe_name.clone())
    }
}

#[cfg(windows)]
impl fmt::Debug for WindowsPipeListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPipeListener")
            .field("pipe_name", &self.pipe_name)
            .field("owner_sid", &"[OWNER ACL]")
            .finish()
    }
}

#[cfg(unix)]
fn prepare_runtime_directory(path: &Path) -> Result<(), DaemonError> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))
            .map_err(|_error| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::UnsafeRuntimePath))?;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(DaemonError::new(DaemonErrorCode::UnsafeRuntimePath));
    }
    Ok(())
}

/// Bounded PEM material shared by HTTP and gRPC TLS listeners.
pub struct TlsMaterial {
    certificate_chain: Vec<u8>,
    private_key: Vec<u8>,
    client_ca: Option<Vec<u8>>,
}

impl TlsMaterial {
    /// Loads regular bounded files and requires a permission-restricted private key.
    pub fn load(files: &TlsFiles) -> Result<Self, DaemonError> {
        let certificate_chain = read_bounded_regular(&files.certificate_chain, false)?;
        let private_key = read_bounded_regular(&files.private_key, true)?;
        let client_ca = files
            .client_ca
            .as_deref()
            .map(|path| read_bounded_regular(path, false))
            .transpose()?;
        Ok(Self {
            certificate_chain,
            private_key,
            client_ca,
        })
    }

    /// Returns proof used to construct a shared request authority.
    #[must_use]
    pub(crate) const fn transport_security(&self) -> SharedTransportSecurity {
        SharedTransportSecurity::verified(self.client_ca.is_some())
    }

    /// Creates Tonic TLS configuration and requires client certificates when a CA is present.
    #[must_use]
    pub fn tonic_config(&self) -> ServerTlsConfig {
        let mut config = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.certificate_chain.clone(),
                self.private_key.clone(),
            ))
            .timeout(TLS_HANDSHAKE_TIMEOUT);
        if let Some(client_ca) = &self.client_ca {
            config = config
                .client_ca_root(Certificate::from_pem(client_ca.clone()))
                .client_auth_optional(false);
        }
        config
    }

    /// Creates the equivalent Rustls configuration for the Axum HTTPS listener.
    pub fn axum_config(&self) -> Result<RustlsConfig, DaemonError> {
        Ok(RustlsConfig::from_config(self.rustls_server_config()?))
    }

    pub(crate) fn rustls_server_config(&self) -> Result<Arc<ServerConfig>, DaemonError> {
        let certificate_chain = CertificateDer::pem_slice_iter(&self.certificate_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
        if certificate_chain.is_empty() {
            return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
        }
        let key = PrivateKeyDer::from_pem_slice(&self.private_key)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
        let mut config = if let Some(client_ca) = &self.client_ca {
            let mut roots = RootCertStore::empty();
            let ca_certificates = CertificateDer::pem_slice_iter(client_ca)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
            if ca_certificates.is_empty() {
                return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
            }
            for certificate in ca_certificates {
                roots
                    .add(certificate)
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificate_chain, key)
                .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?
        } else {
            builder
                .with_no_client_auth()
                .with_single_cert(certificate_chain, key)
                .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?
        };
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// Returns whether configured TLS requires a trusted client certificate.
    #[must_use]
    pub const fn requires_client_certificate(&self) -> bool {
        self.client_ca.is_some()
    }
}

/// Transport-verified client identity attached to an accepted shared HTTP connection.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedTlsConnectionInfo {
    identity: Option<VerifiedClientIdentity>,
}

impl VerifiedTlsConnectionInfo {
    pub(crate) const fn identity(&self) -> Option<&VerifiedClientIdentity> {
        self.identity.as_ref()
    }
}

/// TLS listener that rejects missing or malformed CIGAR SAN identities before HTTP parsing.
pub(crate) struct VerifiedTlsListener {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
    require_client_identity: bool,
    handshakes:
        tokio::task::JoinSet<Option<(TlsStream<tokio::net::TcpStream>, VerifiedTlsConnectionInfo)>>,
}

impl VerifiedTlsListener {
    pub(crate) fn new(
        listener: tokio::net::TcpListener,
        config: Arc<ServerConfig>,
        require_client_identity: bool,
    ) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            require_client_identity,
            handshakes: tokio::task::JoinSet::new(),
        }
    }

    fn start_handshake(&mut self, stream: tokio::net::TcpStream) {
        let acceptor = self.acceptor.clone();
        let timeout = self.handshake_timeout;
        let require_client_identity = self.require_client_identity;
        self.handshakes.spawn(async move {
            let stream = match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => return None,
            };
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .and_then(|certificate| {
                    verified_client_identity_from_der(certificate.as_ref()).ok()
                });
            if require_client_identity && identity.is_none() {
                return None;
            }
            Some((stream, VerifiedTlsConnectionInfo { identity }))
        });
    }
}

impl fmt::Debug for VerifiedTlsListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTlsListener")
            .field("require_client_identity", &self.require_client_identity)
            .finish()
    }
}

impl axum::serve::Listener for VerifiedTlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = VerifiedTlsConnectionInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.handshakes.is_empty() {
                match self.listener.accept().await {
                    Ok((stream, _address)) => self.start_handshake(stream),
                    Err(_error) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                continue;
            }

            tokio::select! {
                completed = self.handshakes.join_next() => {
                    if let Some(Ok(Some(connection))) = completed {
                        return connection;
                    }
                }
                accepted = self.listener.accept(), if self.handshakes.len() < MAX_PENDING_TLS_HANDSHAKES => {
                    match accepted {
                        Ok((stream, _address)) => self.start_handshake(stream),
                        Err(_error) => tokio::time::sleep(Duration::from_millis(20)).await,
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "verified TLS peer identity exists only on accepted connections",
        ))
    }
}

pub(crate) fn verified_client_identity_from_der(
    certificate_der: &[u8],
) -> Result<VerifiedClientIdentity, DaemonError> {
    let (remainder, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    if !remainder.is_empty() {
        return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
    }
    let names = certificate
        .subject_alternative_name()
        .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?
        .ok_or_else(|| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    let mut tenant = None;
    let mut principal = None;
    for name in &names.value.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };
        if let Some(value) = uri.strip_prefix("urn:cigar:tenant:") {
            if tenant.replace(value.to_owned()).is_some() {
                return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
            }
        } else if let Some(value) = uri.strip_prefix("urn:cigar:principal:")
            && principal.replace(value.to_owned()).is_some()
        {
            return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
        }
    }
    VerifiedClientIdentity::from_verified_tls_peer(
        tenant.ok_or_else(|| DaemonError::new(DaemonErrorCode::TlsUnavailable))?,
        principal.ok_or_else(|| DaemonError::new(DaemonErrorCode::TlsUnavailable))?,
    )
    .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsMaterial")
            .field("certificate_chain", &"[CONFIGURED]")
            .field("private_key", &"[REDACTED]")
            .field(
                "client_ca",
                &self.client_ca.as_ref().map(|_| "[CONFIGURED]"),
            )
            .finish()
    }
}

fn read_bounded_regular(path: &Path, private: bool) -> Result<Vec<u8>, DaemonError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_TLS_FILE_BYTES
    {
        return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
        }
    }
    let file =
        File::open(path).map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
    if bytes.len() > capacity || bytes.is_empty() {
        return Err(DaemonError::new(DaemonErrorCode::TlsUnavailable));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::UnixSocketGuard;
    use super::{ListenerPlan, LocalIpcEndpoint};
    #[cfg(unix)]
    use crate::DaemonErrorCode;
    use crate::{ConfigErrorCode, DaemonConfig, DeploymentMode};

    #[cfg(unix)]
    fn local_unix_config(root: &std::path::Path) -> DaemonConfig {
        let state = root.join("state");
        let runtime = root.join("run");
        DaemonConfig {
            mode: DeploymentMode::Local,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: state.clone(),
            runtime_directory: runtime.clone(),
            unix_socket: Some(runtime.join("cigard.sock")),
            windows_named_pipe: None,
            http_listen: None,
            grpc_listen: None,
            local_token_file: None,
            tls: None,
            oidc: None,
            production: crate::ProductionPaths {
                project_directory: root.join("project"),
                metadata_database: state.join("cigar.sqlite3"),
                blob_directory: state.join("blobs"),
                blob_key_reference_directory: state.join("blob-keys"),
                keystore_file: state.join("keystore.cigar"),
                keystore_passphrase_file: root.join("secrets/keystore-passphrase"),
                cursor_signing_key_file: state.join("cursor.key"),
                effect_checkpoint_file: root.join("checkpoints/effects.json"),
                policy_profile_file: root.join("config/policy.json"),
                authority_file: root.join("config/authority.json"),
                source_registry_file: root.join("config/sources.json"),
                effect_registry_file: root.join("config/effects.json"),
            },
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 1_000,
            shutdown_deadline_ms: 1_000,
            max_request_bytes: 1_024,
            max_expansion_ratio: 1,
            workers: crate::WorkerCapacities {
                ingestion: 1,
                indexing: 1,
                invalidation: 1,
                compilation: 1,
                outbox: 1,
                reconciliation: 1,
                lease_cleanup: 1,
                backup: 1,
                garbage_collection: 1,
            },
            resources: crate::ApplicationResourceLimits {
                global_request_concurrency: 16,
                per_tenant_request_concurrency: 4,
                blocking_active: 2,
                blocking_queued: 8,
                idempotency_wait_ms: 1_000,
            },
            telemetry: crate::TelemetrySettings {
                otlp_endpoint: None,
                otlp_ca_certificate_file: None,
                export_timeout_ms: 1_000,
                metric_interval_ms: 1_000,
            },
        }
    }

    #[test]
    fn windows_pipe_abstraction_accepts_only_closed_cigar_namespace() {
        assert!(LocalIpcEndpoint::is_safe_windows_pipe_name(
            r"\\.\pipe\cigar-cigd-v1"
        ));
        assert!(!LocalIpcEndpoint::is_safe_windows_pipe_name(
            r"\\server\pipe\cigar-cigd-v1"
        ));
        assert!(!LocalIpcEndpoint::is_safe_windows_pipe_name(
            r"\\.\pipe\other"
        ));
        assert!(!LocalIpcEndpoint::is_safe_windows_pipe_name(
            r"\\.\pipe\cigar-parent\child"
        ));
        assert!(!LocalIpcEndpoint::is_safe_windows_pipe_name(
            r"\\.\pipe\cigar-"
        ));
    }

    #[test]
    fn listener_plan_rechecks_public_local_bind_refusal() {
        let config = DaemonConfig {
            mode: DeploymentMode::Local,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: "/tmp/cigar-state".into(),
            runtime_directory: "/tmp/cigar-run".into(),
            unix_socket: None,
            windows_named_pipe: None,
            http_listen: Some(std::net::SocketAddr::from(([0, 0, 0, 0], 7443))),
            grpc_listen: None,
            local_token_file: Some("/tmp/cigar-run/token".into()),
            tls: None,
            oidc: None,
            production: crate::ProductionPaths {
                project_directory: "/tmp/cigar-project".into(),
                metadata_database: "/tmp/cigar-state/cigar.sqlite3".into(),
                blob_directory: "/tmp/cigar-state/blobs".into(),
                blob_key_reference_directory: "/tmp/cigar-state/blob-keys".into(),
                keystore_file: "/tmp/cigar-state/keystore.cigar".into(),
                keystore_passphrase_file: "/tmp/cigar-secrets/keystore-passphrase".into(),
                cursor_signing_key_file: "/tmp/cigar-state/cursor.key".into(),
                effect_checkpoint_file: "/tmp/cigar-effect-checkpoints/checkpoints.json".into(),
                policy_profile_file: "/tmp/cigar-config/policy.json".into(),
                authority_file: "/tmp/cigar-config/authority.json".into(),
                source_registry_file: "/tmp/cigar-config/sources.json".into(),
                effect_registry_file: "/tmp/cigar-config/effects.json".into(),
            },
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 1_000,
            shutdown_deadline_ms: 1_000,
            max_request_bytes: 1_024,
            max_expansion_ratio: 1,
            workers: crate::WorkerCapacities {
                ingestion: 1,
                indexing: 1,
                invalidation: 1,
                compilation: 1,
                outbox: 1,
                reconciliation: 1,
                lease_cleanup: 1,
                backup: 1,
                garbage_collection: 1,
            },
            resources: crate::ApplicationResourceLimits {
                global_request_concurrency: 16,
                per_tenant_request_concurrency: 4,
                blocking_active: 2,
                blocking_queued: 8,
                idempotency_wait_ms: 1_000,
            },
            telemetry: crate::TelemetrySettings {
                otlp_endpoint: None,
                otlp_ca_certificate_file: None,
                export_timeout_ms: 1_000,
                metric_interval_ms: 1_000,
            },
        };
        assert_eq!(
            config.validate().err().map(|error| error.code()),
            Some(ConfigErrorCode::UnsafeLocalBind)
        );
        assert!(ListenerPlan::from_config(&config).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_guard_is_owner_private_and_never_unlinks_a_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let config = local_unix_config(&root);
        config.validate()?;
        let socket = config.unix_socket.clone().ok_or("socket path missing")?;
        let (listener, guard) = UnixSocketGuard::bind(&config)?;
        let original = std::fs::symlink_metadata(&socket)?;
        assert_eq!(original.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(original.nlink(), 1);
        assert_eq!(original.mode() & 0o777, 0o600);

        std::fs::remove_file(&socket)?;
        let replacement = std::os::unix::net::UnixListener::bind(&socket)?;
        let replacement_identity = std::fs::symlink_metadata(&socket)?;
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement_identity.dev(), replacement_identity.ino())
        );
        drop(guard);
        let after_drop = std::fs::symlink_metadata(&socket)?;
        assert_eq!(
            (after_drop.dev(), after_drop.ino()),
            (replacement_identity.dev(), replacement_identity.ino())
        );
        drop(replacement);
        std::fs::remove_file(&socket)?;
        drop(listener);

        std::fs::write(&socket, b"must-not-unlink")?;
        assert_eq!(
            UnixSocketGuard::bind(&config)
                .err()
                .map(|error| error.code()),
            Some(DaemonErrorCode::UnsafeRuntimePath)
        );
        assert_eq!(std::fs::read(&socket)?, b"must-not-unlink");
        std::fs::remove_file(&socket)?;

        symlink(root.join("missing-socket-target"), &socket)?;
        assert_eq!(
            UnixSocketGuard::bind(&config)
                .err()
                .map(|error| error.code()),
            Some(DaemonErrorCode::UnsafeRuntimePath)
        );
        assert!(std::fs::symlink_metadata(&socket)?.file_type().is_symlink());
        std::fs::remove_file(&socket)?;

        std::fs::set_permissions(
            &config.runtime_directory,
            std::fs::Permissions::from_mode(0o777),
        )?;
        assert_eq!(
            UnixSocketGuard::bind(&config)
                .err()
                .map(|error| error.code()),
            Some(DaemonErrorCode::UnsafeRuntimePath)
        );
        assert!(!socket.exists());
        Ok(())
    }
}
