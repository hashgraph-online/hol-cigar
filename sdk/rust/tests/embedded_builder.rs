//! Embedded builder validation and object-safety tests.

use cigar_sdk::api::{AuthenticatedIdentity, PrincipalId, TenantId};
use cigar_sdk::{
    ClientTransport, EmbeddedClientBuilder, EmbeddedRuntime, EmbeddedRuntimeConfig,
    EmbeddedRuntimeFactory, ErrorKind, PolicyProfile, SdkError, SdkFuture, StorageProfile,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingFactory {
    starts: Arc<AtomicUsize>,
    identity: Option<AuthenticatedIdentity>,
}

impl EmbeddedRuntimeFactory for CountingFactory {
    fn authoritative_identity(&self) -> Option<AuthenticatedIdentity> {
        self.identity.clone()
    }

    fn start<'a>(
        &'a self,
        _config: EmbeddedRuntimeConfig,
    ) -> SdkFuture<'a, Result<Arc<dyn EmbeddedRuntime>, SdkError>> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(SdkError::transport()) })
    }
}

fn assert_factory_object_safe(_factory: Arc<dyn EmbeddedRuntimeFactory>) {}

fn assert_transport_object_safe(_transport: Arc<dyn ClientTransport>) {}

#[tokio::test]
async fn invalid_profiles_fail_before_workers_start() -> Result<(), Box<dyn std::error::Error>> {
    let starts = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn EmbeddedRuntimeFactory> = Arc::new(CountingFactory {
        starts: starts.clone(),
        identity: None,
    });
    assert_factory_object_safe(factory.clone());
    let builder = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Memory {
            maximum_records: 1_024,
        })
        .identity(TenantId::new("tenant-a")?, PrincipalId::new("principal-a")?);
    let result = builder.build().await;
    let Err(error) = result else {
        return Err("incomplete builder unexpectedly started".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidConfiguration);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn valid_explicit_profiles_reach_factory_once() -> Result<(), Box<dyn std::error::Error>> {
    let starts = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn EmbeddedRuntimeFactory> = Arc::new(CountingFactory {
        starts: starts.clone(),
        identity: None,
    });
    let result = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Memory {
            maximum_records: 1_024,
        })
        .policy_profile(PolicyProfile::DenyAll)
        .identity(TenantId::new("tenant-a")?, PrincipalId::new("principal-a")?)
        .build()
        .await;
    let Err(error) = result else {
        return Err("test factory unexpectedly returned a runtime".into());
    };
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let _assertion: fn(Arc<dyn ClientTransport>) = assert_transport_object_safe;
    Ok(())
}

#[tokio::test]
async fn authoritative_factory_rejects_duplicate_identity_strings()
-> Result<(), Box<dyn std::error::Error>> {
    let starts = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn EmbeddedRuntimeFactory> = Arc::new(CountingFactory {
        starts: starts.clone(),
        identity: Some(AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("derived-tenant")?,
            PrincipalId::new("derived-principal")?,
        )),
    });
    let result = EmbeddedClientBuilder::new(factory)
        .storage_profile(StorageProfile::Memory {
            maximum_records: 1_024,
        })
        .policy_profile(PolicyProfile::DenyAll)
        .identity(
            TenantId::new("caller-tenant")?,
            PrincipalId::new("caller-principal")?,
        )
        .build()
        .await;
    let Err(error) = result else {
        return Err("duplicate identity unexpectedly accepted".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidConfiguration);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    Ok(())
}
