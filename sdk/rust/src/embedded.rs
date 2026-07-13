//! Validated embedded runtime builder and transport.

use crate::{
    Client, ClientTransport, ErrorKind, SdkError, SdkFuture, TransportCall, TransportEventStream,
};
use cigar_api::{
    AuthenticatedIdentity, CancellationToken as ApiCancellationToken, OperationId, PrincipalId,
    RequestContext, ServiceFacade, TenantId, TraceId,
};
use cigar_protocol::{RetryClass, UtcTimestamp};
use futures_util::future::poll_fn;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// SQLite durability choice passed to an embedded runtime factory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteDurability {
    /// Full synchronous durability for production state.
    Full,
    /// Normal synchronous durability for explicitly accepted local tradeoffs.
    Normal,
}

/// Explicit storage profile required before an embedded runtime can start workers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageProfile {
    /// Ephemeral bounded storage intended for tests and deterministic examples.
    Memory {
        /// Maximum retained records across in-memory repositories.
        maximum_records: usize,
    },
    /// Durable single-node SQLite storage.
    Sqlite {
        /// Absolute database path.
        path: PathBuf,
        /// Explicit durability setting.
        durability: SqliteDurability,
        /// Bounded connection count.
        maximum_connections: u16,
    },
}

/// Explicit fail-closed policy profile required by the embedded builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyProfile {
    /// Denies every governed operation; useful for bootstrap verification.
    DenyAll,
    /// Loads a local policy document from an absolute path.
    LocalFile {
        /// Absolute policy document path.
        path: PathBuf,
    },
}

/// Validated configuration supplied to an embedded runtime factory.
#[derive(Clone, Debug)]
pub struct EmbeddedRuntimeConfig {
    storage: StorageProfile,
    policy: PolicyProfile,
}

impl EmbeddedRuntimeConfig {
    /// Returns the explicit storage profile.
    #[must_use]
    pub const fn storage(&self) -> &StorageProfile {
        &self.storage
    }

    /// Returns the explicit policy profile.
    #[must_use]
    pub const fn policy(&self) -> &PolicyProfile {
        &self.policy
    }
}

/// Started embedded runtime retained for the full client lifetime.
pub trait EmbeddedRuntime: Send + Sync {
    /// Returns the frozen transport-neutral service facade.
    fn facade(&self) -> Arc<dyn ServiceFacade>;

    /// Requests graceful runtime shutdown after callers stop using the client.
    fn shutdown<'a>(&'a self) -> SdkFuture<'a, Result<(), SdkError>>;
}

/// Object-safe factory that starts workers only after builder validation succeeds.
pub trait EmbeddedRuntimeFactory: Send + Sync {
    /// Returns a server-derived identity when the factory owns the authoritative identity source.
    /// Generic factories return `None` and require the builder's explicit identity instead.
    fn authoritative_identity(&self) -> Option<AuthenticatedIdentity> {
        None
    }

    /// Starts one runtime from a completely validated configuration.
    fn start<'a>(
        &'a self,
        config: EmbeddedRuntimeConfig,
    ) -> SdkFuture<'a, Result<Arc<dyn EmbeddedRuntime>, SdkError>>;
}

/// Running embedded client paired with its ordered runtime shutdown handle.
pub struct EmbeddedClient {
    client: Client,
    runtime: Arc<dyn EmbeddedRuntime>,
}

impl EmbeddedClient {
    /// Returns the parallel high-level client interface.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Consumes the handle and performs the runtime's full ordered shutdown.
    pub async fn shutdown(self) -> Result<(), SdkError> {
        self.runtime.shutdown().await
    }
}

impl Deref for EmbeddedClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl fmt::Debug for EmbeddedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmbeddedClient { runtime: [RUNNING] }")
    }
}

/// Embedded client builder requiring explicit storage, policy, and identity.
pub struct EmbeddedClientBuilder {
    factory: Arc<dyn EmbeddedRuntimeFactory>,
    storage: Option<StorageProfile>,
    policy: Option<PolicyProfile>,
    tenant: Option<TenantId>,
    principal: Option<PrincipalId>,
}

impl EmbeddedClientBuilder {
    /// Creates an incomplete builder around an injected runtime factory.
    #[must_use]
    pub fn new(factory: Arc<dyn EmbeddedRuntimeFactory>) -> Self {
        Self {
            factory,
            storage: None,
            policy: None,
            tenant: None,
            principal: None,
        }
    }

    /// Selects the required storage profile.
    #[must_use]
    pub fn storage_profile(mut self, storage: StorageProfile) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Selects the required policy profile.
    #[must_use]
    pub fn policy_profile(mut self, policy: PolicyProfile) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Sets the verified identity used only inside this embedded process.
    #[must_use]
    pub fn identity(mut self, tenant: TenantId, principal: PrincipalId) -> Self {
        self.tenant = Some(tenant);
        self.principal = Some(principal);
        self
    }

    /// Validates every profile before invoking the worker-starting factory.
    pub async fn build(self) -> Result<EmbeddedClient, SdkError> {
        let storage = self.storage.ok_or_else(configuration_error)?;
        let policy = self.policy.ok_or_else(configuration_error)?;
        validate_storage(&storage)?;
        validate_policy(&policy)?;
        let supplied_identity = self.tenant.zip(self.principal).map(|(tenant, principal)| {
            AuthenticatedIdentity::from_verified_credentials(tenant, principal)
        });
        let authoritative_identity = self.factory.authoritative_identity();
        if supplied_identity.is_some() && authoritative_identity.is_some() {
            return Err(configuration_error());
        }
        let identity = authoritative_identity
            .or(supplied_identity)
            .ok_or_else(configuration_error)?;
        let runtime = self
            .factory
            .start(EmbeddedRuntimeConfig { storage, policy })
            .await?;
        let transport = Arc::new(EmbeddedTransport {
            runtime: Arc::clone(&runtime),
            identity,
        });
        Ok(EmbeddedClient {
            client: Client::from_transport(transport),
            runtime,
        })
    }
}

impl fmt::Debug for EmbeddedClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedClientBuilder")
            .field("has_storage", &self.storage.is_some())
            .field("has_policy", &self.policy.is_some())
            .field(
                "has_identity",
                &(self.tenant.is_some() && self.principal.is_some()),
            )
            .finish()
    }
}

struct EmbeddedTransport {
    runtime: Arc<dyn EmbeddedRuntime>,
    identity: AuthenticatedIdentity,
}

impl ClientTransport for EmbeddedTransport {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<cigar_api::ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            let api_cancellation = ApiCancellationToken::new();
            let context = embedded_context(&call, self.identity.clone(), api_cancellation.clone())?;
            let facade = self.runtime.facade();
            let future = facade.call(context, call.envelope().clone());
            tokio::select! {
                result = future => result.map_err(SdkError::from_api),
                () = call.cancellation().cancelled() => {
                    api_cancellation.cancel();
                    Err(crate::client::cancelled_error())
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                    api_cancellation.cancel();
                    Err(crate::client::deadline_error())
                }
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async move {
            let api_cancellation = ApiCancellationToken::new();
            let context = embedded_context(&call, self.identity.clone(), api_cancellation.clone())?;
            let facade = self.runtime.facade();
            let source = tokio::select! {
                result = facade.subscribe(context, call.envelope().clone()) => {
                    result.map_err(SdkError::from_api)?
                }
                () = call.cancellation().cancelled() => {
                    api_cancellation.cancel();
                    return Err(crate::client::cancelled_error());
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                    api_cancellation.cancel();
                    return Err(crate::client::deadline_error());
                }
            };
            Ok(bounded_embedded_stream(source, call, api_cancellation))
        })
    }
}

fn bounded_embedded_stream(
    mut source: cigar_api::FacadeEventStream,
    call: TransportCall,
    api_cancellation: ApiCancellationToken,
) -> TransportEventStream {
    let (sender, receiver) = mpsc::channel(32);
    tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                event = poll_fn(|context| source.as_mut().poll_next(context)) => event,
                () = call.cancellation().cancelled() => {
                    let _ignored = sender.send(Err(crate::client::cancelled_error())).await;
                    break;
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                    let _ignored = sender.send(Err(crate::client::deadline_error())).await;
                    break;
                }
            };
            let Some(event) = next else {
                break;
            };
            let terminal = event.is_err();
            if sender
                .send(event.map_err(SdkError::from_api))
                .await
                .is_err()
                || terminal
            {
                break;
            }
        }
        api_cancellation.cancel();
    });
    Box::pin(ReceiverEventStream { receiver })
}

struct ReceiverEventStream {
    receiver: mpsc::Receiver<Result<cigar_api::EventEnvelope, SdkError>>,
}

impl futures_core::Stream for ReceiverEventStream {
    type Item = Result<cigar_api::EventEnvelope, SdkError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

fn embedded_context(
    call: &TransportCall,
    identity: AuthenticatedIdentity,
    cancellation: ApiCancellationToken,
) -> Result<RequestContext, SdkError> {
    let remaining = call
        .deadline()
        .checked_duration_since(Instant::now())
        .ok_or_else(crate::client::deadline_error)?;
    let accepted_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_failure| configuration_error())?
        .as_nanos();
    let accepted_nanos =
        i128::try_from(accepted_nanos).map_err(|_failure| configuration_error())?;
    let remaining_nanos =
        i128::try_from(remaining.as_nanos()).map_err(|_failure| configuration_error())?;
    let deadline_nanos = accepted_nanos
        .checked_add(remaining_nanos)
        .ok_or_else(configuration_error)?;
    let accepted =
        UtcTimestamp::from_unix_nanos(accepted_nanos).map_err(|_failure| configuration_error())?;
    let deadline =
        UtcTimestamp::from_unix_nanos(deadline_nanos).map_err(|_failure| configuration_error())?;
    RequestContext::new(
        identity,
        OperationId::new(call.contract().operation_id).map_err(|_failure| configuration_error())?,
        deadline,
        trace_id()?,
        cancellation,
        accepted,
    )
    .map_err(|_failure| configuration_error())
}

fn trace_id() -> Result<TraceId, SdkError> {
    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_failure| configuration_error())?
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(time.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_failure| configuration_error())?;
    }
    TraceId::new(encoded).map_err(|_failure| configuration_error())
}

fn validate_storage(profile: &StorageProfile) -> Result<(), SdkError> {
    match profile {
        StorageProfile::Memory { maximum_records } if (1..=1_000_000).contains(maximum_records) => {
            Ok(())
        }
        StorageProfile::Sqlite {
            path,
            maximum_connections,
            ..
        } if valid_absolute_file(path) && (1..=64).contains(maximum_connections) => Ok(()),
        _ => Err(configuration_error()),
    }
}

fn validate_policy(profile: &PolicyProfile) -> Result<(), SdkError> {
    match profile {
        PolicyProfile::DenyAll => Ok(()),
        PolicyProfile::LocalFile { path } if valid_absolute_file(path) => Ok(()),
        PolicyProfile::LocalFile { .. } => Err(configuration_error()),
    }
}

fn valid_absolute_file(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some() && path.as_os_str().len() <= 4096
}

const fn configuration_error() -> SdkError {
    SdkError::local(
        ErrorKind::InvalidConfiguration,
        RetryClass::Never,
        "embedded builder configuration is incomplete or invalid",
    )
}
