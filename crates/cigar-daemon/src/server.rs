//! Axum/Tonic listener composition and bounded process shutdown.

use crate::{
    DaemonConfig, DaemonDependencies, DaemonError, DaemonErrorCode, DeploymentMode, JwksRefresh,
    ListenerPlan, LocalBearerToken, LocalIdentity, LocalSocketAuthority, LocalTokenAuthority,
    OperatorAuthorizer, RuntimeShutdownAction, SharedOidcAuthority, ShutdownAction,
    ShutdownCoordinator, ShutdownReceipt, ShutdownStep, TlsMaterial, VerifiedTlsConnectionInfo,
    VerifiedTlsListener, verified_client_identity_from_der,
};
#[cfg(unix)]
use crate::{LocalIpcEndpoint, UnixSocketGuard};
#[cfg(windows)]
use crate::{LocalIpcEndpoint, WindowsPipeListener};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::connect_info::Connected;
use axum::http::Request;
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use axum::serve::IncomingStream;
use cigar_api::{
    GrpcService, RequestAuthority, ServiceFacade, ServiceKernel, TransportConfig, http_router,
    http_routes,
};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::service::Routes;
use tonic::transport::Server;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower::limit::ConcurrencyLimitLayer;
use tower::{Layer, Service};
use tower_http::limit::RequestBodyLimitLayer;

const MAX_CONNECTION_REQUESTS: usize = 256;
const MAX_GRPC_STREAMS: u32 = 128;
const STREAM_BUFFER_CAPACITY: usize = 32;

/// Addresses bound by a running daemon; no credential or protected identity is included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAddresses {
    /// Local Unix socket path, when active on Unix.
    pub local_ipc: Option<PathBuf>,
    /// Local Windows named-pipe endpoint, when active on Windows.
    pub windows_named_pipe: Option<String>,
    /// Bound HTTP TCP address, including an assigned ephemeral port.
    pub http: Option<SocketAddr>,
    /// Bound gRPC TCP address, including an assigned ephemeral port.
    pub grpc: Option<SocketAddr>,
}

/// Successful bounded daemon shutdown receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRunReceipt {
    /// Addresses that were active before shutdown.
    pub addresses: ServerAddresses,
    /// Exact ordered lifecycle shutdown outcome.
    pub shutdown: ShutdownReceipt,
}

struct AuthoritySet {
    local_ipc: Option<Arc<dyn RequestAuthority>>,
    network: Option<Arc<dyn RequestAuthority>>,
}

/// Fully validated daemon server that still requires a complete injected service facade.
pub struct DaemonServer {
    config: DaemonConfig,
    plan: ListenerPlan,
    dependencies: DaemonDependencies,
    authorities: AuthoritySet,
    service_facade: Arc<dyn ServiceFacade>,
    tls: Option<Arc<TlsMaterial>>,
    #[cfg(windows)]
    local_pipe_owner_sid: Option<Arc<str>>,
}

impl DaemonServer {
    /// Creates a local server whose tenant and principal are derived from a canonical project
    /// directory and its filesystem owner, never from request headers or environment variables.
    pub fn local_for_project(
        config: DaemonConfig,
        dependencies: DaemonDependencies,
        project_root: &std::path::Path,
    ) -> Result<Self, DaemonError> {
        let identity = LocalIdentity::from_project_root(project_root)
            .map_err(|_error| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
        Self::local(config, dependencies, identity)
    }

    /// Creates a local server using permission-restricted IPC and/or loopback bearer auth.
    pub fn local(
        config: DaemonConfig,
        dependencies: DaemonDependencies,
        identity: LocalIdentity,
    ) -> Result<Self, DaemonError> {
        if config.mode != DeploymentMode::Local {
            return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
        }
        let plan = ListenerPlan::from_config(&config)?;
        #[cfg(windows)]
        let local_pipe_owner_sid = if matches!(
            plan.local_ipc.as_ref(),
            Some(LocalIpcEndpoint::WindowsNamedPipe(_))
        ) {
            Some(Arc::from(identity.windows_owner_sid().ok_or_else(
                || DaemonError::new(DaemonErrorCode::AuthorityUnavailable),
            )?))
        } else {
            None
        };
        let service_facade = Arc::clone(&dependencies.facade);
        let local_ipc = plan
            .local_ipc
            .as_ref()
            .map(|_endpoint| {
                LocalSocketAuthority::new(identity.clone(), Arc::clone(&dependencies.telemetry))
                    .map(|authority| Arc::new(authority) as Arc<dyn RequestAuthority>)
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))
            })
            .transpose()?;
        let network = if plan.http.is_some() || plan.grpc.is_some() {
            let token_file = config
                .local_token_file
                .as_deref()
                .ok_or_else(|| DaemonError::new(DaemonErrorCode::CredentialUnavailable))?;
            let token = load_or_create_local_token(token_file)?;
            Some(Arc::new(
                LocalTokenAuthority::new(token, identity, Arc::clone(&dependencies.telemetry))
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?,
            ) as Arc<dyn RequestAuthority>)
        } else {
            None
        };
        Ok(Self {
            config,
            plan,
            dependencies,
            authorities: AuthoritySet { local_ipc, network },
            service_facade,
            tls: None,
            #[cfg(windows)]
            local_pipe_owner_sid,
        })
    }

    /// Creates a shared server with TLS on both listeners and pinned OIDC verification.
    pub fn shared(
        config: DaemonConfig,
        dependencies: DaemonDependencies,
        jwks_refresh: Arc<dyn JwksRefresh>,
        operators: Arc<dyn OperatorAuthorizer>,
    ) -> Result<Self, DaemonError> {
        if config.mode != DeploymentMode::Shared {
            return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
        }
        let plan = ListenerPlan::from_config(&config)?;
        let tls_files = config
            .tls
            .as_ref()
            .ok_or_else(|| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
        let tls = Arc::new(TlsMaterial::load(tls_files)?);
        let oidc_settings = config
            .oidc
            .clone()
            .ok_or_else(|| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
        let oidc = Arc::new(crate::OidcAuthenticator::new(oidc_settings, jwks_refresh));
        let authority = Arc::new(
            SharedOidcAuthority::new(
                oidc,
                operators,
                tls.transport_security(),
                Arc::clone(&dependencies.telemetry),
            )
            .map_err(|_error| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?,
        ) as Arc<dyn RequestAuthority>;
        let service_facade = Arc::clone(&dependencies.facade);
        Ok(Self {
            config,
            plan,
            dependencies,
            authorities: AuthoritySet {
                local_ipc: None,
                network: Some(authority),
            },
            service_facade,
            tls: Some(tls),
            #[cfg(windows)]
            local_pipe_owner_sid: None,
        })
    }

    /// Runs ordered recovery, binds all configured listeners, and starts serving.
    pub async fn start(self) -> Result<RunningDaemon, DaemonError> {
        self.dependencies
            .startup
            .run(self.config.shutdown_deadline())
            .await
            .map_err(|_error| DaemonError::new(DaemonErrorCode::StartupFailed))?;
        let bound = match BoundListeners::bind(&self).await {
            Ok(bound) => bound,
            Err(error) => {
                self.dependencies.readiness_gate.close();
                self.dependencies.telemetry.record_listener_failure();
                return Err(error);
            }
        };
        RunningDaemon::spawn(self, bound)
    }

    /// Starts the complete local production runtime without binding a listener.
    ///
    /// Embedded callers receive the exact governed facade used by HTTP and gRPC while retaining
    /// startup recovery, bounded workers, readiness, and ordered graceful shutdown. Shared-mode
    /// identity is intentionally unavailable without its TLS/OIDC transport boundary.
    pub async fn start_embedded(self) -> Result<RunningEmbeddedDaemon, DaemonError> {
        if self.config.mode != DeploymentMode::Local {
            return Err(DaemonError::new(DaemonErrorCode::InvalidConfiguration));
        }
        self.dependencies
            .startup
            .run(self.config.shutdown_deadline())
            .await
            .map_err(|_error| DaemonError::new(DaemonErrorCode::StartupFailed))?;
        let (shutdown_sender, _shutdown_receiver) = watch::channel(false);
        let shutdown = runtime_shutdown_coordinator(&self, shutdown_sender.clone())?;
        Ok(RunningEmbeddedDaemon {
            facade: Arc::clone(&self.service_facade),
            shutdown,
            shutdown_sender,
            shutdown_deadline: self.config.shutdown_deadline(),
            readiness_gate: Arc::clone(&self.dependencies.readiness_gate),
            workers: Arc::clone(&self.dependencies.workers),
            shutdown_started: AtomicBool::new(false),
            shutdown_complete: AtomicBool::new(false),
        })
    }

    /// Runs until the supplied signal resolves or a listener fails unexpectedly.
    pub async fn run_until<F>(self, signal: F) -> Result<DaemonRunReceipt, DaemonError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut running = self.start().await?;
        let listener_failed = tokio::select! {
            () = signal => false,
            failure = running.failure_receiver.recv() => failure.is_some(),
        };
        let receipt = running.shutdown().await?;
        if listener_failed {
            Err(DaemonError::new(DaemonErrorCode::ListenerFailed))
        } else {
            Ok(receipt)
        }
    }
}

/// Listener-free production runtime used by embedded CLI and SDK clients.
pub struct RunningEmbeddedDaemon {
    facade: Arc<dyn ServiceFacade>,
    shutdown: ShutdownCoordinator,
    shutdown_sender: watch::Sender<bool>,
    shutdown_deadline: Duration,
    readiness_gate: Arc<crate::ReadinessGate>,
    workers: Arc<crate::DaemonWorkers>,
    shutdown_started: AtomicBool,
    shutdown_complete: AtomicBool,
}

impl RunningEmbeddedDaemon {
    /// Returns the same complete governed service facade used by daemon transports.
    #[must_use]
    pub fn facade(&self) -> Arc<dyn ServiceFacade> {
        Arc::clone(&self.facade)
    }

    /// Runs the full ordered graceful shutdown exactly once.
    pub async fn shutdown(&self) -> Result<ShutdownReceipt, DaemonError> {
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return Err(DaemonError::new(DaemonErrorCode::ShutdownIncomplete));
        }
        let receipt = self.shutdown.run(self.shutdown_deadline).await;
        if receipt.failed.is_some() {
            Err(DaemonError::new(DaemonErrorCode::ShutdownIncomplete))
        } else {
            self.shutdown_complete.store(true, Ordering::Release);
            Ok(receipt)
        }
    }
}

impl fmt::Debug for RunningEmbeddedDaemon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningEmbeddedDaemon")
            .field("facade", &"[COMPLETE GOVERNED FACADE]")
            .field("ready", &self.readiness_gate.is_open())
            .field(
                "shutdown_started",
                &self.shutdown_started.load(Ordering::Acquire),
            )
            .field(
                "shutdown_complete",
                &self.shutdown_complete.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl Drop for RunningEmbeddedDaemon {
    fn drop(&mut self) {
        if !self.shutdown_complete.load(Ordering::Acquire) {
            self.readiness_gate.close();
            self.workers.runtime().stop_accepting();
            let _ignored = self.shutdown_sender.send(true);
        }
    }
}

impl fmt::Debug for DaemonServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonServer")
            .field("config", &self.config)
            .field("plan", &self.plan)
            .field("dependencies", &self.dependencies)
            .field("authorities", &"[INJECTED]")
            .field("tls", &self.tls)
            .finish()
    }
}

/// Active daemon listeners with explicit bounded shutdown.
pub struct RunningDaemon {
    addresses: ServerAddresses,
    shutdown: ShutdownCoordinator,
    shutdown_sender: watch::Sender<bool>,
    shutdown_deadline: Duration,
    listener_tasks: Vec<JoinHandle<Result<(), DaemonError>>>,
    failure_receiver: mpsc::Receiver<&'static str>,
    readiness_gate: Arc<crate::ReadinessGate>,
    workers: Arc<crate::DaemonWorkers>,
    #[cfg(unix)]
    socket_guard: Option<UnixSocketGuard>,
}

impl RunningDaemon {
    fn spawn(server: DaemonServer, bound: BoundListeners) -> Result<Self, DaemonError> {
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let (failure_sender, failure_receiver) = mpsc::channel(3);
        let mut listener_tasks = Vec::new();

        let transport = TransportConfig::with_compression_limits(
            server.config.request_deadline(),
            server.config.request_deadline(),
            STREAM_BUFFER_CAPACITY,
            server.config.max_expansion_ratio,
        )
        .and_then(|transport| {
            transport.with_maximum_expanded_request_bytes(server.config.max_request_bytes)
        })
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
        let metrics_observer: Arc<dyn cigar_api::TransportMetricsObserver> =
            server.dependencies.telemetry.clone();
        let network_kernel = server.authorities.network.as_ref().map(|authority| {
            ServiceKernel::new(
                Arc::clone(&server.service_facade),
                Arc::clone(authority),
                transport,
            )
            .with_metrics_observer(Arc::clone(&metrics_observer))
        });
        let ipc_kernel = server.authorities.local_ipc.as_ref().map(|authority| {
            ServiceKernel::new(
                Arc::clone(&server.service_facade),
                Arc::clone(authority),
                transport,
            )
            .with_metrics_observer(Arc::clone(&metrics_observer))
        });

        #[cfg(unix)]
        if let Some(listener) = bound.local_listener {
            let kernel = ipc_kernel
                .clone()
                .ok_or_else(|| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
            let app = multiplex_router(kernel, server.config.max_request_bytes)?;
            listener_tasks.push(spawn_plain_axum(
                "local_ipc",
                listener,
                app,
                shutdown_receiver.clone(),
                failure_sender.clone(),
                Arc::clone(&server.dependencies.telemetry),
            ));
        }

        #[cfg(windows)]
        if let Some(listener) = bound.local_listener {
            let kernel = ipc_kernel
                .clone()
                .ok_or_else(|| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
            let app = multiplex_router(kernel, server.config.max_request_bytes)?;
            listener_tasks.push(spawn_plain_axum(
                "local_ipc",
                listener,
                app,
                shutdown_receiver.clone(),
                failure_sender.clone(),
                Arc::clone(&server.dependencies.telemetry),
            ));
        }

        if let Some(http) = bound.http_listener {
            let kernel = network_kernel
                .clone()
                .ok_or_else(|| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
            let app = bounded_http_router(kernel, server.config.max_request_bytes);
            listener_tasks.push(match http {
                BoundHttp::Plain(listener) => spawn_plain_axum(
                    "http",
                    listener,
                    app,
                    shutdown_receiver.clone(),
                    failure_sender.clone(),
                    Arc::clone(&server.dependencies.telemetry),
                ),
                BoundHttp::Tls(listener) => spawn_tls_axum(
                    listener,
                    app,
                    shutdown_receiver.clone(),
                    failure_sender.clone(),
                    Arc::clone(&server.dependencies.telemetry),
                )?,
            });
        }

        if let Some(listener) = bound.grpc_listener {
            let kernel = network_kernel
                .ok_or_else(|| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
            listener_tasks.push(spawn_grpc(GrpcListenerTask {
                listener,
                kernel,
                tls: server.tls.as_ref().map(Arc::clone),
                maximum_message_bytes: server.config.max_request_bytes,
                deadline: server.config.request_deadline(),
                shutdown: shutdown_receiver,
                failures: failure_sender,
                telemetry: Arc::clone(&server.dependencies.telemetry),
            })?);
        }

        let shutdown = runtime_shutdown_coordinator(&server, shutdown_sender.clone())?;

        Ok(Self {
            addresses: bound.addresses,
            shutdown,
            shutdown_sender,
            shutdown_deadline: server.config.shutdown_deadline(),
            listener_tasks,
            failure_receiver,
            readiness_gate: server.dependencies.readiness_gate,
            workers: server.dependencies.workers,
            #[cfg(unix)]
            socket_guard: bound.socket_guard,
        })
    }

    /// Returns the exact bound addresses without exposing credentials.
    #[must_use]
    pub const fn addresses(&self) -> &ServerAddresses {
        &self.addresses
    }

    /// Stops admissions and dispatch claims, drains workers, persists state, and flushes telemetry.
    pub async fn shutdown(mut self) -> Result<DaemonRunReceipt, DaemonError> {
        let started = Instant::now();
        let shutdown = self.shutdown.run(self.shutdown_deadline).await;
        let join_result =
            join_listener_tasks(&mut self.listener_tasks, self.shutdown_deadline, started).await;
        if shutdown.failed.is_some() || join_result.is_err() {
            return Err(DaemonError::new(DaemonErrorCode::ShutdownIncomplete));
        }
        #[cfg(unix)]
        drop(self.socket_guard.take());
        Ok(DaemonRunReceipt {
            addresses: self.addresses.clone(),
            shutdown,
        })
    }
}

fn runtime_shutdown_coordinator(
    server: &DaemonServer,
    shutdown_sender: watch::Sender<bool>,
) -> Result<ShutdownCoordinator, DaemonError> {
    let actions: Vec<Arc<dyn ShutdownAction>> = ShutdownStep::ALL
        .into_iter()
        .map(|step| {
            Arc::new(RuntimeShutdownAction {
                step,
                readiness: Arc::clone(&server.dependencies.readiness_gate),
                workers: Arc::clone(&server.dependencies.workers),
                blocking_pool: Arc::clone(&server.dependencies.blocking_pool),
                hooks: Arc::clone(&server.dependencies.shutdown_hooks),
                telemetry: Arc::clone(&server.dependencies.telemetry),
                listener_shutdown: shutdown_sender.clone(),
                telemetry_timeout: server.config.shutdown_deadline(),
            }) as Arc<dyn ShutdownAction>
        })
        .collect();
    ShutdownCoordinator::new(actions, Arc::clone(&server.dependencies.readiness_gate))
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        self.readiness_gate.close();
        self.workers.runtime().stop_accepting();
        let _ignored = self.shutdown_sender.send(true);
        for task in &self.listener_tasks {
            task.abort();
        }
    }
}

async fn join_listener_tasks(
    tasks: &mut Vec<JoinHandle<Result<(), DaemonError>>>,
    deadline: Duration,
    started: Instant,
) -> Result<(), DaemonError> {
    while let Some(mut task) = tasks.pop() {
        let remaining = deadline
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        match tokio::time::timeout(remaining, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => return Err(error),
            Ok(Err(_join_error)) => {
                return Err(DaemonError::new(DaemonErrorCode::ListenerFailed));
            }
            Err(_elapsed) => {
                task.abort();
                for pending in tasks.drain(..) {
                    pending.abort();
                }
                return Err(DaemonError::new(DaemonErrorCode::ShutdownIncomplete));
            }
        }
    }
    Ok(())
}

impl fmt::Debug for RunningDaemon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningDaemon")
            .field("addresses", &self.addresses)
            .field("listener_count", &self.listener_tasks.len())
            .finish()
    }
}

struct BoundListeners {
    addresses: ServerAddresses,
    #[cfg(unix)]
    local_listener: Option<tokio::net::UnixListener>,
    #[cfg(unix)]
    socket_guard: Option<UnixSocketGuard>,
    #[cfg(windows)]
    local_listener: Option<WindowsPipeListener>,
    http_listener: Option<BoundHttp>,
    grpc_listener: Option<TcpListener>,
}

enum BoundHttp {
    Plain(TcpListener),
    Tls(VerifiedTlsListener),
}

impl BoundListeners {
    async fn bind(server: &DaemonServer) -> Result<Self, DaemonError> {
        #[cfg(unix)]
        let (local_listener, socket_guard, local_ipc) =
            if matches!(server.plan.local_ipc, Some(LocalIpcEndpoint::UnixSocket(_))) {
                let (listener, guard) = UnixSocketGuard::bind(&server.config)?;
                (
                    Some(listener),
                    Some(guard),
                    server.config.unix_socket.clone(),
                )
            } else {
                (None, None, None)
            };

        #[cfg(not(unix))]
        let local_ipc = None;

        #[cfg(windows)]
        let (local_listener, windows_named_pipe) =
            if let Some(LocalIpcEndpoint::WindowsNamedPipe(pipe_name)) = &server.plan.local_ipc {
                let owner_sid = server
                    .local_pipe_owner_sid
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| DaemonError::new(DaemonErrorCode::AuthorityUnavailable))?;
                (
                    Some(WindowsPipeListener::bind(pipe_name.clone(), owner_sid)?),
                    Some(pipe_name.clone()),
                )
            } else {
                (None, None)
            };

        #[cfg(not(windows))]
        let windows_named_pipe = None;

        let (http_listener, http_address) = if let Some(address) = server.plan.http {
            if server.plan.tls_required {
                let tls = server
                    .tls
                    .as_ref()
                    .ok_or_else(|| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
                let listener = TcpListener::bind(address)
                    .await
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
                let bound = listener
                    .local_addr()
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
                (
                    Some(BoundHttp::Tls(VerifiedTlsListener::new(
                        listener,
                        tls.rustls_server_config()?,
                        tls.requires_client_certificate(),
                    ))),
                    Some(bound),
                )
            } else {
                let listener = TcpListener::bind(address)
                    .await
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
                let bound = listener
                    .local_addr()
                    .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
                (Some(BoundHttp::Plain(listener)), Some(bound))
            }
        } else {
            (None, None)
        };

        let (grpc_listener, grpc_address) = if let Some(address) = server.plan.grpc {
            let listener = TcpListener::bind(address)
                .await
                .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
            let bound = listener
                .local_addr()
                .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerBindFailed))?;
            (Some(listener), Some(bound))
        } else {
            (None, None)
        };

        Ok(Self {
            addresses: ServerAddresses {
                local_ipc,
                windows_named_pipe,
                http: http_address,
                grpc: grpc_address,
            },
            #[cfg(unix)]
            local_listener,
            #[cfg(unix)]
            socket_guard,
            #[cfg(windows)]
            local_listener,
            http_listener,
            grpc_listener,
        })
    }
}

fn load_or_create_local_token(
    path: &std::path::Path,
) -> Result<Arc<LocalBearerToken>, DaemonError> {
    let token = if path.exists() {
        LocalBearerToken::read_file(path)
    } else {
        LocalBearerToken::create_file(path).or_else(|_error| LocalBearerToken::read_file(path))
    }
    .map_err(|_error| DaemonError::new(DaemonErrorCode::CredentialUnavailable))?;
    Ok(Arc::new(token))
}

fn grpc_routes(kernel: ServiceKernel, maximum_message_bytes: usize) -> Result<Routes, DaemonError> {
    let effective_limit = maximum_message_bytes.min(cigar_api::MAX_GRPC_MESSAGE_BYTES);
    let service = GrpcService::new(kernel)
        .with_max_message_bytes(effective_limit)
        .map_err(|_error| DaemonError::new(DaemonErrorCode::InvalidConfiguration))?;
    let mut builder = Routes::builder();
    builder
        .add_service(service.clone().catalog_server())
        .add_service(service.clone().context_server())
        .add_service(service.clone().space_server())
        .add_service(service.clone().handoff_server())
        .add_service(service.clone().effect_server())
        .add_service(service.clone().replay_server())
        .add_service(service.operations_server());
    Ok(builder.routes())
}

fn bounded_http_router(kernel: ServiceKernel, maximum_body_bytes: usize) -> Router {
    http_router(kernel)
        .layer(RequestBodyLimitLayer::new(maximum_body_bytes))
        .layer(ConcurrencyLimitLayer::new(MAX_CONNECTION_REQUESTS))
}

impl Connected<IncomingStream<'_, VerifiedTlsListener>> for VerifiedTlsConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, VerifiedTlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

async fn attach_verified_tls_identity(
    ConnectInfo(info): ConnectInfo<VerifiedTlsConnectionInfo>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(identity) = info.identity() {
        request.extensions_mut().insert(identity.clone());
    }
    next.run(request).await
}

fn multiplex_router(
    kernel: ServiceKernel,
    maximum_body_bytes: usize,
) -> Result<Router, DaemonError> {
    let tonic = grpc_routes(kernel.clone(), maximum_body_bytes)?.into_axum_router();
    Ok(http_routes(kernel)
        .merge(tonic)
        .layer(RequestBodyLimitLayer::new(maximum_body_bytes))
        .layer(ConcurrencyLimitLayer::new(MAX_CONNECTION_REQUESTS)))
}

fn spawn_plain_axum<L>(
    label: &'static str,
    listener: L,
    app: Router,
    shutdown: watch::Receiver<bool>,
    failures: mpsc::Sender<&'static str>,
    telemetry: Arc<crate::DaemonTelemetry>,
) -> JoinHandle<Result<(), DaemonError>>
where
    L: axum::serve::Listener,
    L::Addr: fmt::Debug,
{
    tokio::spawn(async move {
        let observed_shutdown = shutdown.clone();
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(wait_shutdown(shutdown))
            .await
            .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerFailed));
        report_unexpected_exit(label, &observed_shutdown, failures, &telemetry).await;
        result
    })
}

fn spawn_tls_axum(
    listener: VerifiedTlsListener,
    app: Router,
    shutdown: watch::Receiver<bool>,
    failures: mpsc::Sender<&'static str>,
    telemetry: Arc<crate::DaemonTelemetry>,
) -> Result<JoinHandle<Result<(), DaemonError>>, DaemonError> {
    Ok(tokio::spawn(async move {
        let observed_shutdown = shutdown.clone();
        let app = app.layer(from_fn(attach_verified_tls_identity));
        let result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<VerifiedTlsConnectionInfo>(),
        )
        .with_graceful_shutdown(wait_shutdown(shutdown))
        .await
        .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerFailed));
        report_unexpected_exit("http_tls", &observed_shutdown, failures, &telemetry).await;
        result
    }))
}

#[derive(Clone, Copy, Debug)]
struct VerifiedIdentityLayer;

impl<S> Layer<S> for VerifiedIdentityLayer {
    type Service = VerifiedIdentityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifiedIdentityService { inner }
    }
}

#[derive(Clone, Debug)]
struct VerifiedIdentityService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for VerifiedIdentityService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let identity = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(TlsConnectInfo::peer_certs)
            .and_then(|certificates| certificates.first().cloned())
            .and_then(|certificate| verified_client_identity_from_der(certificate.as_ref()).ok());
        if let Some(identity) = identity {
            request.extensions_mut().insert(identity);
        }
        self.inner.call(request)
    }
}

struct GrpcListenerTask {
    listener: TcpListener,
    kernel: ServiceKernel,
    tls: Option<Arc<TlsMaterial>>,
    maximum_message_bytes: usize,
    deadline: Duration,
    shutdown: watch::Receiver<bool>,
    failures: mpsc::Sender<&'static str>,
    telemetry: Arc<crate::DaemonTelemetry>,
}

fn spawn_grpc(task: GrpcListenerTask) -> Result<JoinHandle<Result<(), DaemonError>>, DaemonError> {
    let tls = task.tls.as_deref().map(TlsMaterial::tonic_config);
    let routes = grpc_routes(task.kernel, task.maximum_message_bytes)?;
    Ok(tokio::spawn(async move {
        let observed_shutdown = task.shutdown.clone();
        let mut builder = Server::builder()
            .layer(VerifiedIdentityLayer)
            .concurrency_limit_per_connection(MAX_CONNECTION_REQUESTS)
            .max_concurrent_streams(MAX_GRPC_STREAMS)
            .timeout(task.deadline);
        if let Some(tls) = tls {
            builder = builder
                .tls_config(tls)
                .map_err(|_error| DaemonError::new(DaemonErrorCode::TlsUnavailable))?;
        }
        let router = builder.add_routes(routes);
        let result = router
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(task.listener),
                wait_shutdown(task.shutdown),
            )
            .await
            .map_err(|_error| DaemonError::new(DaemonErrorCode::ListenerFailed));
        report_unexpected_exit("grpc", &observed_shutdown, task.failures, &task.telemetry).await;
        result
    }))
}

async fn wait_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

async fn report_unexpected_exit(
    label: &'static str,
    shutdown: &watch::Receiver<bool>,
    failures: mpsc::Sender<&'static str>,
    telemetry: &crate::DaemonTelemetry,
) {
    if !*shutdown.borrow() {
        telemetry.record_listener_failure();
        let _ignored = failures.send(label).await;
    }
}

#[cfg(test)]
mod tests {
    use super::DaemonServer;
    use crate::{
        BlockingPool, DaemonConfig, DaemonDependencies, DaemonErrorCode, DaemonTelemetry,
        DaemonWorkers, DenyAllOperators, JwksRefresh, JwksRefreshFuture, JwksRefreshRequest,
        JwksRefreshResponse, LifecycleFuture, LocalIdentity, OidcSettings, OperationalFacade,
        QueueErrorCode, ReadinessGate, ShutdownHookFuture, ShutdownHooks, ShutdownStep,
        StartupAction, StartupCoordinator, StartupStep, SystemRuntimeClock, TlsFiles,
        WorkerCapacities, WorkerJob, WorkerKind, WorkerReceivers, WorkerRuntime,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(target_os = "macos")]
    use cigar_api::generated::{
        HttpMethod, IdempotencyRequirement, OPERATIONS, OperationContract, RevisionRequirement,
        StreamKind,
    };
    use cigar_api::{
        ApiError, CancellationToken, EventEnvelope, FacadeEventStream, OperationId,
        ProbeObservation, ReadinessAggregator, ReadinessComponent, ReadinessProbe, RequestContext,
        RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture, TenantId, TraceId,
    };
    use cigar_protocol::{ErrorCode, RecordId, UtcTimestamp};
    use futures_core::Stream;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use serde_json::json;
    #[cfg(target_os = "macos")]
    use std::fmt::Write as _;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsConnector;

    #[cfg(target_os = "macos")]
    type OperationPathBindings = (String, Vec<(String, String)>);

    struct SuccessfulStartup(StartupStep);

    impl StartupAction for SuccessfulStartup {
        fn step(&self) -> StartupStep {
            self.0
        }

        fn execute(&self) -> LifecycleFuture<'_> {
            Box::pin(async { Ok(()) })
        }
    }

    struct HealthyProbe(ReadinessComponent);

    impl ReadinessProbe for HealthyProbe {
        fn component(&self) -> ReadinessComponent {
            self.0
        }

        fn check(&self) -> ProbeObservation {
            ProbeObservation::healthy()
        }
    }

    struct ToggleProbe {
        component: ReadinessComponent,
        healthy: Arc<AtomicBool>,
    }

    impl ReadinessProbe for ToggleProbe {
        fn component(&self) -> ReadinessComponent {
            self.component
        }

        fn check(&self) -> ProbeObservation {
            if self.healthy.load(Ordering::Acquire) {
                ProbeObservation::healthy()
            } else {
                ProbeObservation::unhealthy(ErrorCode::DependencyDegraded)
            }
        }
    }

    #[derive(Default)]
    struct TestShutdownHooks {
        checkpoints: AtomicUsize,
        releases: AtomicUsize,
    }

    impl ShutdownHooks for TestShutdownHooks {
        fn checkpoint_workers(&self) -> ShutdownHookFuture<'_> {
            Box::pin(async move {
                self.checkpoints.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn release_renewable_leases(&self) -> ShutdownHookFuture<'_> {
            Box::pin(async move {
                self.releases.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    struct StaticJwks {
        document: Vec<u8>,
        valid_until_unix_seconds: i64,
    }

    impl JwksRefresh for StaticJwks {
        fn refresh(&self, _request: JwksRefreshRequest) -> JwksRefreshFuture {
            let response = JwksRefreshResponse {
                document: self.document.clone(),
                valid_until_unix_seconds: self.valid_until_unix_seconds,
            };
            Box::pin(async move { Ok(response) })
        }
    }

    struct MtlsFixture {
        ca_pem: String,
        ca_der: Vec<u8>,
        server_certificate_pem: String,
        server_key_pem: String,
        client_certificate_der: Vec<u8>,
        client_key_der: Vec<u8>,
    }

    fn mtls_fixture() -> Result<MtlsFixture, Box<dyn std::error::Error>> {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new())?;
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = CertifiedIssuer::self_signed(ca_parameters, KeyPair::generate()?)?;

        let mut server_parameters = CertificateParams::new(vec!["localhost".to_owned()])?;
        server_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_certificate = server_parameters.signed_by(&server_key, &ca)?;

        let mut client_parameters = CertificateParams::new(Vec::<String>::new())?;
        client_parameters.subject_alt_names = vec![
            SanType::URI("urn:cigar:tenant:tenant-a".try_into()?),
            SanType::URI("urn:cigar:principal:service-a".try_into()?),
        ];
        client_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate()?;
        let client_certificate = client_parameters.signed_by(&client_key, &ca)?;

        Ok(MtlsFixture {
            ca_pem: ca.pem(),
            ca_der: ca.der().to_vec(),
            server_certificate_pem: server_certificate.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_certificate_der: client_certificate.der().to_vec(),
            client_key_der: client_key.serialize_der(),
        })
    }

    fn write_tls_files(
        root: &Path,
        fixture: &MtlsFixture,
    ) -> Result<TlsFiles, Box<dyn std::error::Error>> {
        let certificate_chain = root.join("server.pem");
        let private_key = root.join("server-key.pem");
        let client_ca = root.join("client-ca.pem");
        std::fs::write(&certificate_chain, &fixture.server_certificate_pem)?;
        std::fs::write(&private_key, &fixture.server_key_pem)?;
        std::fs::write(&client_ca, &fixture.ca_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(TlsFiles {
            certificate_chain,
            private_key,
            client_ca: Some(client_ca),
        })
    }

    fn client_tls_config(
        fixture: &MtlsFixture,
    ) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(fixture.ca_der.clone()))?;
        let client_certificate = CertificateDer::from(fixture.client_certificate_der.clone());
        let client_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.client_key_der.clone()));
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![client_certificate], client_key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    fn client_tls_config_without_certificate(
        fixture: &MtlsFixture,
    ) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(fixture.ca_der.clone()))?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    fn unix_seconds() -> Result<i64, Box<dyn std::error::Error>> {
        Ok(i64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )?)
    }

    fn oidc_token(
        secret: &cigar_crypto::SecretBytes,
        tenant: &str,
        principal: &str,
        now: i64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg": "EdDSA", "kid": "key-1", "typ": "JWT"}),
        )?);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "iss": "https://issuer.example",
            "aud": "cigar-api",
            "sub": principal,
            "tenant": tenant,
            "iat": now,
            "nbf": now.saturating_sub(1),
            "exp": now.saturating_add(300),
        }))?);
        let signing_input = format!("{header}.{claims}");
        let signature = cigar_crypto::sign_ed25519(secret, signing_input.as_bytes())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    async fn mtls_get(
        address: SocketAddr,
        fixture: &MtlsFixture,
        token: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let stream = tokio::net::TcpStream::connect(address).await?;
        let connector = TlsConnector::from(client_tls_config(fixture)?);
        let server_name = ServerName::try_from("localhost")?.to_owned();
        let mut stream = connector.connect(server_name, stream).await?;
        let request = format!(
            "GET /v1/catalog/sources/source-a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    async fn tls_get_without_client_certificate(
        address: SocketAddr,
        fixture: &MtlsFixture,
        token: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let stream = tokio::net::TcpStream::connect(address).await?;
        let connector = TlsConnector::from(client_tls_config_without_certificate(fixture)?);
        let server_name = ServerName::try_from("localhost")?.to_owned();
        let mut stream = connector.connect(server_name, stream).await?;
        let request = format!(
            "GET /v1/catalog/sources/source-a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    struct TestFacade {
        calls: AtomicUsize,
        correlation: RecordId,
    }

    struct OneEvent(Option<EventEnvelope>);

    impl Stream for OneEvent {
        type Item = Result<EventEnvelope, ApiError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.take().map(Ok))
        }
    }

    impl ServiceFacade for TestFacade {
        fn call<'a>(
            &'a self,
            _context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let operation = request.operation_id().as_str().to_owned();
            let correlation = self.correlation.clone();
            Box::pin(async move {
                ResponseEnvelope::new(operation, vec![0xf6], None, None)
                    .map_err(|_error| ApiError::new(ErrorCode::Internal, correlation))
            })
        }

        fn subscribe<'a>(
            &'a self,
            _context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let operation = request.operation_id().as_str().to_owned();
            let correlation = self.correlation.clone();
            Box::pin(async move {
                let event = EventEnvelope::new(operation, "event-1", vec![0xf6])
                    .map_err(|_error| ApiError::new(ErrorCode::Internal, correlation))?;
                Ok(Box::pin(OneEvent(Some(event))) as FacadeEventStream)
            })
        }
    }

    struct TestServerInputs {
        dependencies: DaemonDependencies,
        readiness: Arc<ReadinessGate>,
        runtime: Arc<WorkerRuntime>,
        facade: Arc<TestFacade>,
        hooks: Arc<TestShutdownHooks>,
        _receivers: WorkerReceivers,
        telemetry: Arc<DaemonTelemetry>,
        dependency_health: Arc<AtomicBool>,
    }

    fn worker_capacities() -> WorkerCapacities {
        WorkerCapacities {
            ingestion: 2,
            indexing: 2,
            invalidation: 2,
            compilation: 2,
            outbox: 2,
            reconciliation: 2,
            lease_cleanup: 2,
            backup: 2,
            garbage_collection: 2,
        }
    }

    fn test_inputs() -> Result<TestServerInputs, Box<dyn std::error::Error>> {
        let readiness = Arc::new(ReadinessGate::default());
        let startup_actions: Vec<Arc<dyn StartupAction>> = StartupStep::ALL
            .into_iter()
            .map(|step| Arc::new(SuccessfulStartup(step)) as Arc<dyn StartupAction>)
            .collect();
        let startup = StartupCoordinator::new(startup_actions, Arc::clone(&readiness))?;
        let readiness_components = [
            ReadinessComponent::MetadataStore,
            ReadinessComponent::MigrationLevel,
            ReadinessComponent::BlobReadWrite,
            ReadinessComponent::PolicySnapshot,
            ReadinessComponent::JournalIntegrity,
            ReadinessComponent::MandatoryIndex,
            ReadinessComponent::KeyProvider,
            ReadinessComponent::WorkerHeartbeat,
        ];
        let dependency_health = Arc::new(AtomicBool::new(true));
        let probes = readiness_components
            .into_iter()
            .map(|component| {
                if component == ReadinessComponent::MetadataStore {
                    Arc::new(ToggleProbe {
                        component,
                        healthy: Arc::clone(&dependency_health),
                    }) as Arc<dyn ReadinessProbe>
                } else {
                    Arc::new(HealthyProbe(component)) as Arc<dyn ReadinessProbe>
                }
            })
            .collect();
        let aggregator = Arc::new(ReadinessAggregator::new(probes)?);
        let (runtime, receivers) =
            WorkerRuntime::new(&worker_capacities(), Arc::new(SystemRuntimeClock::new()))?;
        let runtime = Arc::new(runtime);
        let workers = Arc::new(DaemonWorkers::new(
            Arc::clone(&runtime),
            Arc::clone(&readiness),
        ));
        let hooks = Arc::new(TestShutdownHooks::default());
        let facade = Arc::new(TestFacade {
            calls: AtomicUsize::new(0),
            correlation: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        });
        let telemetry = Arc::new(DaemonTelemetry::local());
        let delegate: Arc<dyn ServiceFacade> = facade.clone();
        let operational_config =
            local_tcp_config(Path::new("/tmp"), SocketAddr::from(([127, 0, 0, 1], 0)));
        let complete_test_facade: Arc<dyn ServiceFacade> = Arc::new(OperationalFacade::new(
            delegate,
            &operational_config,
            Arc::clone(&aggregator),
            Arc::clone(&readiness),
            Arc::clone(&workers),
            Arc::clone(&telemetry),
        )?);
        let dependencies = DaemonDependencies {
            facade: complete_test_facade,
            startup,
            readiness: aggregator,
            readiness_gate: Arc::clone(&readiness),
            workers,
            blocking_pool: Arc::new(BlockingPool::new(2, 2)?),
            shutdown_hooks: hooks.clone(),
            telemetry: Arc::clone(&telemetry),
        };
        Ok(TestServerInputs {
            dependencies,
            readiness,
            runtime,
            facade,
            hooks,
            _receivers: receivers,
            telemetry,
            dependency_health,
        })
    }

    fn local_tcp_config(root: &Path, address: SocketAddr) -> DaemonConfig {
        DaemonConfig {
            mode: crate::DeploymentMode::Local,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: root.join("state"),
            runtime_directory: root.join("runtime"),
            unix_socket: None,
            windows_named_pipe: None,
            http_listen: Some(address),
            grpc_listen: None,
            local_token_file: Some(root.join("local.token")),
            tls: None,
            oidc: None,
            production: production_paths(root),
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 1_000,
            shutdown_deadline_ms: 2_000,
            max_request_bytes: 64 * 1024,
            max_expansion_ratio: 8,
            workers: worker_capacities(),
            resources: resource_limits(),
            telemetry: telemetry_settings(),
        }
    }

    fn shared_config(root: &Path, tls: TlsFiles, grpc_address: SocketAddr) -> DaemonConfig {
        DaemonConfig {
            mode: crate::DeploymentMode::Shared,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: root.join("state"),
            runtime_directory: root.join("runtime"),
            unix_socket: None,
            windows_named_pipe: None,
            http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            grpc_listen: Some(grpc_address),
            local_token_file: None,
            tls: Some(tls),
            oidc: Some(OidcSettings {
                issuer: "https://issuer.example".to_owned(),
                audience: "cigar-api".to_owned(),
                tenant_claim: "tenant".to_owned(),
                jwks_max_age_seconds: 300,
                jwks_refresh_timeout_ms: 100,
                clock_skew_seconds: 30,
                max_token_bytes: 4_096,
            }),
            production: production_paths(root),
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: Some(shared_storage(root)),
            request_deadline_ms: 1_000,
            shutdown_deadline_ms: 2_000,
            max_request_bytes: 64 * 1024,
            max_expansion_ratio: 8,
            workers: worker_capacities(),
            resources: resource_limits(),
            telemetry: telemetry_settings(),
        }
    }

    #[cfg(unix)]
    fn local_unix_config(root: &Path) -> DaemonConfig {
        DaemonConfig {
            mode: crate::DeploymentMode::Local,
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: root.join("state"),
            runtime_directory: root.to_path_buf(),
            unix_socket: Some(root.join("cigard.sock")),
            windows_named_pipe: None,
            http_listen: None,
            grpc_listen: None,
            local_token_file: None,
            tls: None,
            oidc: None,
            production: production_paths(root),
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 1_000,
            shutdown_deadline_ms: 2_000,
            max_request_bytes: 64 * 1024,
            max_expansion_ratio: 8,
            workers: worker_capacities(),
            resources: resource_limits(),
            telemetry: telemetry_settings(),
        }
    }

    fn resource_limits() -> crate::ApplicationResourceLimits {
        crate::ApplicationResourceLimits {
            global_request_concurrency: 32,
            per_tenant_request_concurrency: 8,
            blocking_active: 2,
            blocking_queued: 16,
            idempotency_wait_ms: 1_000,
        }
    }

    fn telemetry_settings() -> crate::TelemetrySettings {
        crate::TelemetrySettings {
            otlp_endpoint: None,
            otlp_ca_certificate_file: None,
            export_timeout_ms: 1_000,
            metric_interval_ms: 1_000,
        }
    }

    fn production_paths(root: &Path) -> crate::ProductionPaths {
        crate::ProductionPaths {
            project_directory: root.to_path_buf(),
            metadata_database: root.join("state/cigar.sqlite3"),
            active_store_descriptor: None,
            blob_directory: root.join("state/blobs"),
            blob_key_reference_directory: root.join("state/blob-keys"),
            keystore_file: root.join("state/keystore.cigar"),
            keystore_passphrase_file: root.join("secrets/keystore-passphrase"),
            cursor_signing_key_file: root.join("state/cursor.key"),
            effect_checkpoint_file: root.join("effect-checkpoints/checkpoints.json"),
            policy_profile_file: root.join("config/policy.json"),
            authority_file: root.join("config/authority.json"),
            source_registry_file: root.join("config/sources.json"),
            effect_registry_file: root.join("config/effects.json"),
        }
    }

    fn shared_storage(root: &Path) -> crate::SharedStorageSettings {
        crate::SharedStorageSettings {
            postgres: crate::SharedPostgresSettings {
                runtime_url_file: root.join("secrets/postgres-runtime-url"),
                migrator_url_file: root.join("secrets/postgres-migrator-url"),
                server_name: "postgres.example".to_owned(),
                ca_certificate_file: root.join("secrets/postgres-ca.crt"),
                minimum_connections: 2,
                maximum_connections: 32,
                acquire_timeout_ms: 5_000,
                statement_timeout_ms: 30_000,
                lock_timeout_ms: 5_000,
                idle_transaction_timeout_ms: 30_000,
            },
            object: crate::SharedObjectSettings {
                endpoint: "https://objects.example".to_owned(),
                region: "us-east-1".to_owned(),
                bucket: "cigar-shared".to_owned(),
                prefix: "production".to_owned(),
                path_style: false,
                access_key_file: root.join("secrets/object-access-key"),
                secret_key_file: root.join("secrets/object-secret-key"),
                security_token_file: Some(root.join("secrets/object-session-token")),
                wrapping_keys_file: root.join("config/object-wrapping-keys.json"),
                blinding_key_file: root.join("secrets/object-blinding-key"),
            },
        }
    }

    async fn tcp_get(
        address: SocketAddr,
        path: &str,
        authorization: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let authorization = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}Connection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8(response)?)
    }

    #[cfg(target_os = "macos")]
    fn operation_path_and_parameters(
        template: &str,
    ) -> Result<OperationPathBindings, Box<dyn std::error::Error>> {
        let mut path = template.to_owned();
        let mut parameters = Vec::new();
        while let Some(open) = path.find('{') {
            let relative_close = path[open + 1..]
                .find('}')
                .ok_or("unclosed operation path template")?;
            let close = open + 1 + relative_close;
            let name = path[open + 1..close].to_owned();
            let value = format!("{name}-v1").replace('_', "-");
            path.replace_range(open..=close, &value);
            parameters.push((name, value));
        }
        parameters.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok((path, parameters))
    }

    #[cfg(target_os = "macos")]
    fn unix_operation_request(
        operation: &OperationContract,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (path, parameters) = operation_path_and_parameters(operation.http_path)?;
        let idempotency = (operation.idempotency_requirement == IdempotencyRequirement::Required)
            .then_some("unix-matrix-key");
        let revision = (operation.revision_requirement == RevisionRequirement::Required)
            .then_some("unix-matrix-revision");
        let mut headers = String::new();
        if let Some(value) = idempotency {
            write!(&mut headers, "Idempotency-Key: {value}\r\n")?;
        }
        if let Some(value) = revision {
            write!(&mut headers, "If-Match: {value}\r\n")?;
        }
        let method = match operation.http_method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        if operation.http_method == HttpMethod::Get {
            return Ok(format!(
                "{method} {path} HTTP/1.1\r\nHost: local\r\n{headers}Connection: close\r\n\r\n"
            )
            .into_bytes());
        }

        let path_parameters = parameters
            .into_iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect::<Vec<_>>();
        let mut body = json!({
            "operation_id": operation.operation_id,
            "payload_cbor": URL_SAFE_NO_PAD.encode([0xa0]),
            "path_parameters": path_parameters,
        });
        let object = body
            .as_object_mut()
            .ok_or("operation request body must be an object")?;
        if let Some(value) = idempotency {
            object.insert("idempotency_key".to_owned(), json!(value));
        }
        if let Some(value) = revision {
            object.insert("expected_revision".to_owned(), json!(value));
        }
        let body = serde_json::to_vec(&body)?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        Ok(request)
    }

    fn readiness_payload(response: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let (_headers, body) = response
            .split_once("\r\n\r\n")
            .ok_or("HTTP response body missing")?;
        let wire: serde_json::Value = serde_json::from_str(body)?;
        let encoded = wire
            .get("payload_cbor")
            .and_then(serde_json::Value::as_str)
            .ok_or("readiness payload missing")?;
        let cbor = URL_SAFE_NO_PAD.decode(encoded)?;
        let node = cigar_canon::from_deterministic_cbor(&cbor)?;
        Ok(serde_json::from_slice(&cigar_canon::to_normalized_json(
            &node,
        )?)?)
    }

    fn worker_job() -> Result<WorkerJob, Box<dyn std::error::Error>> {
        Ok(WorkerJob {
            tenant: TenantId::new("tenant-local")?,
            record_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
            expected_revision: None,
        })
    }

    #[tokio::test]
    async fn embedded_start_calls_exact_facade_and_runs_ordered_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let config = local_tcp_config(&root, "127.0.0.1:0".parse()?);
        let inputs = test_inputs()?;
        let readiness = Arc::clone(&inputs.readiness);
        let hooks = Arc::clone(&inputs.hooks);
        let facade = Arc::clone(&inputs.facade);
        let identity = LocalIdentity::from_project_root(&root)?;
        let server = DaemonServer::local(config, inputs.dependencies, identity.clone())?;
        let running = server.start_embedded().await?;
        assert!(readiness.is_open());

        let accepted_nanos =
            i128::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let accepted = UtcTimestamp::from_unix_nanos(accepted_nanos)?;
        let deadline = UtcTimestamp::from_unix_nanos(
            accepted_nanos
                .checked_add(1_000_000_000)
                .ok_or("deadline overflow")?,
        )?;
        let context = RequestContext::new(
            identity.authenticated(),
            OperationId::new("getSourceStatus")?,
            deadline,
            TraceId::new("00000000000000000000000000000001")?,
            CancellationToken::new(),
            accepted,
        )?;
        let request = RequestEnvelope::new(
            "getSourceStatus",
            Vec::new(),
            None,
            None,
            None,
            None,
            Vec::new(),
        )?;
        let response = running.facade().call(context, request).await?;
        assert_eq!(response.operation_id().as_str(), "getSourceStatus");
        assert_eq!(facade.calls.load(Ordering::SeqCst), 1);

        let receipt = running.shutdown().await?;
        assert_eq!(receipt.completed, ShutdownStep::ALL);
        assert!(receipt.failed.is_none());
        assert!(!readiness.is_open());
        assert_eq!(hooks.checkpoints.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.releases.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn local_tcp_bearer_start_request_and_shutdown_are_real()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let config = local_tcp_config(&root, "127.0.0.1:0".parse()?);
        let token_path = config
            .local_token_file
            .clone()
            .ok_or_else(|| std::io::Error::other("token path missing"))?;
        let inputs = test_inputs()?;
        let readiness = Arc::clone(&inputs.readiness);
        let runtime = Arc::clone(&inputs.runtime);
        let hooks = Arc::clone(&inputs.hooks);
        let facade = Arc::clone(&inputs.facade);
        let server = DaemonServer::local_for_project(config, inputs.dependencies, &root)?;
        let running = server.start().await?;
        let address = running
            .addresses()
            .http
            .ok_or_else(|| std::io::Error::other("HTTP listener missing"))?;
        assert!(readiness.is_open());

        let unauthorized = tcp_get(address, "/v1/catalog/sources/source-a", None).await?;
        assert!(unauthorized.starts_with("HTTP/1.1 401"));
        assert_eq!(facade.calls.load(Ordering::SeqCst), 0);

        let token = std::fs::read_to_string(&token_path)?;
        let authorization = format!("Bearer {token}");
        let authorized = tcp_get(
            address,
            "/v1/catalog/sources/source-a",
            Some(&authorization),
        )
        .await?;
        assert!(authorized.starts_with("HTTP/1.1 200"));
        assert!(authorized.contains("\"operation_id\":\"getSourceStatus\""));
        assert_eq!(facade.calls.load(Ordering::SeqCst), 1);

        let ready = tcp_get(address, "/readyz", None).await?;
        assert!(ready.starts_with("HTTP/1.1 200"));
        let ready_payload = readiness_payload(&ready)?;
        assert_eq!(ready_payload.get("ready"), Some(&json!(true)));
        assert_eq!(
            ready_payload
                .pointer("/dependency_report/components")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(8)
        );
        inputs.dependency_health.store(false, Ordering::Release);
        let unhealthy_dependency = tcp_get(address, "/readyz", None).await?;
        assert!(unhealthy_dependency.starts_with("HTTP/1.1 503"));
        let unhealthy_payload = readiness_payload(&unhealthy_dependency)?;
        assert_eq!(unhealthy_payload.get("ready"), Some(&json!(false)));
        let metadata = unhealthy_payload
            .pointer("/dependency_report/components")
            .and_then(serde_json::Value::as_array)
            .and_then(|components| {
                components
                    .iter()
                    .find(|component| component.get("name") == Some(&json!("metadata_store")))
            })
            .ok_or("metadata readiness component missing")?;
        assert_eq!(metadata.get("status"), Some(&json!("unhealthy")));
        assert_eq!(metadata.get("reason"), Some(&json!("DEPENDENCY_DEGRADED")));
        let unhealthy_diagnostics =
            tcp_get(address, "/v1/diagnostics", Some(&authorization)).await?;
        assert!(unhealthy_diagnostics.starts_with("HTTP/1.1 200"));
        let unhealthy_diagnostics_payload = readiness_payload(&unhealthy_diagnostics)?;
        assert_eq!(
            unhealthy_diagnostics_payload.get("ready"),
            Some(&json!(false))
        );
        inputs.dependency_health.store(true, Ordering::Release);
        readiness.close();
        let closed_lifecycle_gate = tcp_get(address, "/readyz", None).await?;
        assert!(closed_lifecycle_gate.starts_with("HTTP/1.1 503"));
        let closed_payload = readiness_payload(&closed_lifecycle_gate)?;
        assert_eq!(closed_payload.get("ready"), Some(&json!(false)));
        assert_eq!(closed_payload.get("gate_open"), Some(&json!(false)));

        let receipt = running.shutdown().await?;
        assert_eq!(receipt.shutdown.completed, ShutdownStep::ALL);
        assert!(receipt.shutdown.failed.is_none());
        assert!(!readiness.is_open());
        assert_eq!(hooks.checkpoints.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.releases.load(Ordering::SeqCst), 1);
        let queue = runtime
            .queue(WorkerKind::Outbox)
            .ok_or_else(|| std::io::Error::other("outbox queue missing"))?;
        assert_eq!(
            queue
                .try_enqueue(worker_job()?)
                .err()
                .map(|error| error.code()),
            Some(QueueErrorCode::NotAccepting)
        );
        Ok(())
    }

    #[tokio::test]
    async fn shared_http_requires_mtls_oidc_binding_and_skips_stalled_handshakes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let fixture = mtls_fixture()?;
        let tls = write_tls_files(&root, &fixture)?;
        let now = unix_seconds()?;
        let oidc_secret = cigar_crypto::generate_ed25519_secret()?;
        let oidc_public = cigar_crypto::ed25519_public_key(&oidc_secret)?;
        let jwks = serde_json::to_vec(&json!({"keys": [{
            "alg": "EdDSA",
            "crv": "Ed25519",
            "kid": "key-1",
            "kty": "OKP",
            "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(oidc_public),
        }]}))?;
        let refresh = Arc::new(StaticJwks {
            document: jwks,
            valid_until_unix_seconds: now.saturating_add(600),
        });
        let grpc_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let grpc_address = grpc_reservation.local_addr()?;
        drop(grpc_reservation);
        let inputs = test_inputs()?;
        let facade = Arc::clone(&inputs.facade);
        let server = DaemonServer::shared(
            shared_config(&root, tls, grpc_address),
            inputs.dependencies,
            refresh,
            Arc::new(DenyAllOperators),
        )?;
        let running = server.start().await?;
        let address = running
            .addresses()
            .http
            .ok_or_else(|| std::io::Error::other("HTTPS listener missing"))?;

        let stalled_first = tokio::net::TcpStream::connect(address).await?;
        let stalled_second = tokio::net::TcpStream::connect(address).await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let valid = oidc_token(&oidc_secret, "tenant-a", "service-a", now)?;
        let without_certificate = tokio::time::timeout(
            Duration::from_millis(150),
            tls_get_without_client_certificate(address, &fixture, &valid),
        )
        .await;
        assert!(match without_certificate {
            Ok(Ok(response)) => !response.starts_with("HTTP/1.1 200"),
            Ok(Err(_error)) => true,
            Err(_elapsed) => false,
        });
        let authorized = tokio::time::timeout(
            Duration::from_millis(150),
            mtls_get(address, &fixture, &valid),
        )
        .await??;
        assert!(authorized.starts_with("HTTP/1.1 200"));
        assert_eq!(facade.calls.load(Ordering::SeqCst), 1);

        let wrong_principal = oidc_token(&oidc_secret, "tenant-a", "service-b", now)?;
        let principal_mismatch = mtls_get(address, &fixture, &wrong_principal).await?;
        assert!(principal_mismatch.starts_with("HTTP/1.1 403"));
        let wrong_tenant = oidc_token(&oidc_secret, "tenant-b", "service-a", now)?;
        let tenant_mismatch = mtls_get(address, &fixture, &wrong_tenant).await?;
        assert!(tenant_mismatch.starts_with("HTTP/1.1 403"));
        assert_eq!(facade.calls.load(Ordering::SeqCst), 1);

        drop(stalled_first);
        drop(stalled_second);
        running.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn shared_http_allows_oidc_over_tls_when_service_mtls_is_not_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let fixture = mtls_fixture()?;
        let mut tls = write_tls_files(&root, &fixture)?;
        tls.client_ca = None;
        let now = unix_seconds()?;
        let oidc_secret = cigar_crypto::generate_ed25519_secret()?;
        let oidc_public = cigar_crypto::ed25519_public_key(&oidc_secret)?;
        let refresh = Arc::new(StaticJwks {
            document: serde_json::to_vec(&json!({"keys": [{
                "alg": "EdDSA", "crv": "Ed25519", "kid": "key-1", "kty": "OKP",
                "use": "sig", "x": URL_SAFE_NO_PAD.encode(oidc_public),
            }]}))?,
            valid_until_unix_seconds: now.saturating_add(600),
        });
        let grpc_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let grpc_address = grpc_reservation.local_addr()?;
        drop(grpc_reservation);
        let inputs = test_inputs()?;
        let facade = Arc::clone(&inputs.facade);
        let server = DaemonServer::shared(
            shared_config(&root, tls, grpc_address),
            inputs.dependencies,
            refresh,
            Arc::new(DenyAllOperators),
        )?;
        let running = server.start().await?;
        let address = running
            .addresses()
            .http
            .ok_or_else(|| std::io::Error::other("HTTPS listener missing"))?;
        let valid = oidc_token(&oidc_secret, "tenant-a", "service-a", now)?;
        let response = tls_get_without_client_certificate(address, &fixture, &valid).await?;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(facade.calls.load(Ordering::SeqCst), 1);
        running.shutdown().await?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_unix_socket_multiplexes_http_and_shuts_down_cleanly()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let config = local_unix_config(&root);
        let socket = config
            .unix_socket
            .clone()
            .ok_or_else(|| std::io::Error::other("Unix socket missing"))?;
        let inputs = test_inputs()?;
        let readiness = Arc::clone(&inputs.readiness);
        let server = DaemonServer::local(
            config,
            inputs.dependencies,
            LocalIdentity::new("tenant-local", "user-local")?,
        )?;
        let running = server.start().await?;
        let mut stream = tokio::net::UnixStream::connect(&socket).await?;
        stream
            .write_all(b"GET /v1/version HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("\"operation_id\":\"getVersion\""));
        running.shutdown().await?;
        assert!(!readiness.is_open());
        assert!(!socket.exists());
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_unix_socket_routes_all_45_operations_through_the_generated_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let config = local_unix_config(&root);
        let socket = config
            .unix_socket
            .clone()
            .ok_or_else(|| std::io::Error::other("Unix socket missing"))?;
        let inputs = test_inputs()?;
        let facade = Arc::clone(&inputs.facade);
        let server = DaemonServer::local(
            config,
            inputs.dependencies,
            LocalIdentity::new("tenant-local", "user-local")?,
        )?;
        let running = server.start().await?;
        let mut observed = Vec::with_capacity(OPERATIONS.len());

        for operation in OPERATIONS {
            let mut stream = tokio::net::UnixStream::connect(&socket).await?;
            stream
                .write_all(&unix_operation_request(operation)?)
                .await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            let response = String::from_utf8(response)?;
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "{} returned a non-success response",
                operation.operation_id
            );
            if operation.operation_id == "getMetrics" {
                let (headers, body) = response
                    .split_once("\r\n\r\n")
                    .ok_or("OpenMetrics response body missing")?;
                let content_type = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-type")
                        .then(|| value.trim())
                });
                assert_eq!(
                    content_type,
                    Some("application/openmetrics-text; version=1.0.0; charset=utf-8")
                );
                assert!(body.len() <= cigar_api::MAX_OPERATION_PAYLOAD_BYTES);
                assert!(body.ends_with("# EOF\n"));
            } else if operation.stream_kind == StreamKind::ServerStream {
                assert!(response.contains("id: event-1"));
                assert!(
                    response.contains(&format!("\"operation_id\":\"{}\"", operation.operation_id))
                );
            } else {
                let (_headers, body) = response
                    .split_once("\r\n\r\n")
                    .ok_or("HTTP response body missing")?;
                let wire: serde_json::Value = serde_json::from_str(body)?;
                assert_eq!(
                    wire.get("operation_id").and_then(serde_json::Value::as_str),
                    Some(operation.operation_id)
                );
            }
            observed.push(operation.operation_id);
        }

        assert_eq!(observed.len(), 45);
        assert_eq!(
            observed,
            OPERATIONS
                .iter()
                .map(|entry| entry.operation_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            facade.calls.load(Ordering::SeqCst),
            OPERATIONS
                .iter()
                .filter(|entry| entry.service != "OperationsService")
                .count()
        );
        running.shutdown().await?;
        assert!(!socket.exists());
        Ok(())
    }

    #[tokio::test]
    async fn listener_bind_collision_closes_readiness_and_reports_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = occupied.local_addr()?;
        let directory = tempfile::tempdir()?;
        let root: PathBuf = directory.path().canonicalize()?;
        let inputs = test_inputs()?;
        let readiness = Arc::clone(&inputs.readiness);
        let telemetry = Arc::clone(&inputs.telemetry);
        let server = DaemonServer::local(
            local_tcp_config(&root, address),
            inputs.dependencies,
            LocalIdentity::new("tenant-local", "user-local")?,
        )?;
        let error = match server.start().await {
            Err(error) => error,
            Ok(running) => {
                drop(running);
                return Err(std::io::Error::other("occupied listener unexpectedly bound").into());
            }
        };
        assert_eq!(error.code(), DaemonErrorCode::ListenerBindFailed);
        assert!(!readiness.is_open());
        assert_eq!(telemetry.snapshot().listener_failures, 1);
        Ok(())
    }
}
