//! Concrete production embedded runtime backed by `cigar-daemon`.

use crate::{
    EmbeddedRuntime, EmbeddedRuntimeConfig, EmbeddedRuntimeFactory, ErrorKind, PolicyProfile,
    SdkError, SdkFuture, SqliteDurability, StorageProfile,
};
use cigar_daemon::{
    DaemonConfig, DeploymentMode, LocalIdentity, RunningEmbeddedDaemon, compose_production_server,
};
use cigar_protocol::RetryClass;
use std::fmt;
use std::sync::Arc;

/// Production factory that composes and starts the complete listener-free daemon runtime.
///
/// The SDK builder's explicit storage and policy profiles must exactly match the trusted daemon
/// configuration before composition opens a database or starts recovery workers.
#[derive(Clone)]
pub struct DaemonEmbeddedRuntimeFactory {
    config: DaemonConfig,
    identity: cigar_api::AuthenticatedIdentity,
}

impl DaemonEmbeddedRuntimeFactory {
    /// Creates a production factory from one validated local daemon configuration.
    pub fn new(config: DaemonConfig) -> Result<Self, SdkError> {
        config
            .validate()
            .map_err(|_failure| configuration_error())?;
        if config.mode != DeploymentMode::Local {
            return Err(configuration_error());
        }
        let identity = LocalIdentity::from_project_root(&config.production.project_directory)
            .map_err(|_failure| configuration_error())?
            .authenticated();
        Ok(Self { config, identity })
    }

    /// Returns the validated daemon configuration used for composition.
    #[must_use]
    pub const fn config(&self) -> &DaemonConfig {
        &self.config
    }
}

impl EmbeddedRuntimeFactory for DaemonEmbeddedRuntimeFactory {
    fn authoritative_identity(&self) -> Option<cigar_api::AuthenticatedIdentity> {
        Some(self.identity.clone())
    }

    fn start<'a>(
        &'a self,
        config: EmbeddedRuntimeConfig,
    ) -> SdkFuture<'a, Result<Arc<dyn EmbeddedRuntime>, SdkError>> {
        let daemon_config = self.config.clone();
        Box::pin(async move {
            validate_profile_binding(&daemon_config, &config)?;
            let server =
                tokio::task::spawn_blocking(move || compose_production_server(daemon_config))
                    .await
                    .map_err(|_failure| startup_error())?
                    .map_err(|_failure| startup_error())?;
            let running = server
                .start_embedded()
                .await
                .map_err(|_failure| startup_error())?;
            Ok(Arc::new(DaemonEmbeddedRuntime { running }) as Arc<dyn EmbeddedRuntime>)
        })
    }
}

impl fmt::Debug for DaemonEmbeddedRuntimeFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonEmbeddedRuntimeFactory")
            .field("mode", &self.config.mode)
            .field("state_directory", &self.config.state_directory)
            .field("production", &"[EXPLICIT TRUSTED PATHS]")
            .finish()
    }
}

struct DaemonEmbeddedRuntime {
    running: RunningEmbeddedDaemon,
}

impl EmbeddedRuntime for DaemonEmbeddedRuntime {
    fn facade(&self) -> Arc<dyn cigar_api::ServiceFacade> {
        self.running.facade()
    }

    fn shutdown<'a>(&'a self) -> SdkFuture<'a, Result<(), SdkError>> {
        Box::pin(async move {
            self.running
                .shutdown()
                .await
                .map(|_receipt| ())
                .map_err(|_failure| startup_error())
        })
    }
}

fn validate_profile_binding(
    daemon: &DaemonConfig,
    embedded: &EmbeddedRuntimeConfig,
) -> Result<(), SdkError> {
    let storage_matches = matches!(
        embedded.storage(),
        StorageProfile::Sqlite {
            path,
            durability: SqliteDurability::Full,
            maximum_connections: 1..=64,
        } if path == &daemon.production.metadata_database
    );
    let policy_matches = matches!(
        embedded.policy(),
        PolicyProfile::LocalFile { path } if path == &daemon.production.policy_profile_file
    );
    if storage_matches && policy_matches {
        Ok(())
    } else {
        Err(configuration_error())
    }
}

const fn configuration_error() -> SdkError {
    SdkError::local(
        ErrorKind::InvalidConfiguration,
        RetryClass::Never,
        "embedded SDK profiles do not match the daemon production configuration",
    )
}

const fn startup_error() -> SdkError {
    SdkError::local(
        ErrorKind::Transport,
        RetryClass::Never,
        "embedded production runtime failed to start or shut down",
    )
}
