//! Durable mapping from authenticated transport subjects to protocol domain identities.

use cigar_api::RequestContext;
use cigar_canon::parse_strict_json;
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_protocol::{ContentDigest, RecordId};
use cigar_store::{
    CancellationToken, ServiceBatch, ServiceError, ServiceErrorCode, ServiceExpectedVersion,
    ServiceListQuery, ServiceListScope, ServiceRecordLocator, ServiceRecordSelection,
    ServiceRecordWrite, ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

const TENANT_NAMESPACE: &str = "daemon.domain-tenant.v1";
const PRINCIPAL_NAMESPACE: &str = "daemon.domain-principal.v1";
const TENANT_SCHEMA: &str = "cigar.domain-tenant-mapping.v1";
const PRINCIPAL_SCHEMA: &str = "cigar.domain-principal-mapping.v1";
const MAX_RESOLUTION_RETRIES: usize = 32;
const TENANT_LIST_PAGE_SIZE: usize = 1_000;

/// Stable content-free identity-resolution failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainIdentityErrorCode {
    /// The request was cancelled before a mapping became durable.
    Cancelled,
    /// A generated or retained mapping was malformed.
    InvalidMapping,
    /// The durable identity repository could not safely complete resolution.
    Unavailable,
}

/// Content-free domain identity error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DomainIdentityError {
    code: DomainIdentityErrorCode,
}

impl DomainIdentityError {
    pub(crate) const fn new(code: DomainIdentityErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> DomainIdentityErrorCode {
        self.code
    }
}

impl fmt::Debug for DomainIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DomainIdentityError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DomainIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "domain identity resolution failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for DomainIdentityError {}

/// Server-authoritative protocol identities for one authenticated request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDomainIdentity {
    /// Stable tenant partition identity shared by every principal in the authenticated tenant.
    pub tenant_id: RecordId,
    /// Stable principal identity scoped to the authenticated tenant.
    pub principal_id: RecordId,
}

/// Maps verified transport identities to stable protocol identities without trusting payload IDs.
pub trait DomainIdentityResolver: Send + Sync {
    /// Resolves or durably allocates the identities for one authenticated request.
    fn resolve(
        &self,
        context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, DomainIdentityError>;
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantMapping {
    schema_version: String,
    subject_digest: ContentDigest,
    tenant_id: RecordId,
}

impl TenantMapping {
    fn validate(&self, expected_digest: &ContentDigest) -> Result<(), DomainIdentityError> {
        if self.schema_version == TENANT_SCHEMA && &self.subject_digest == expected_digest {
            Ok(())
        } else {
            Err(invalid_mapping())
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalMapping {
    schema_version: String,
    tenant_subject_digest: ContentDigest,
    principal_subject_digest: ContentDigest,
    tenant_id: RecordId,
    principal_id: RecordId,
}

impl PrincipalMapping {
    fn validate(
        &self,
        tenant_digest: &ContentDigest,
        principal_digest: &ContentDigest,
        tenant_id: &RecordId,
    ) -> Result<(), DomainIdentityError> {
        if self.schema_version == PRINCIPAL_SCHEMA
            && &self.tenant_subject_digest == tenant_digest
            && &self.principal_subject_digest == principal_digest
            && &self.tenant_id == tenant_id
        {
            Ok(())
        } else {
            Err(invalid_mapping())
        }
    }
}

/// Restart-safe durable resolver over the shared service repository.
pub struct DurableDomainIdentityResolver {
    repository: Arc<dyn ServiceRepository>,
    storage_tenant_id: RecordId,
    ids: MonotonicUuidV7Generator,
}

impl DurableDomainIdentityResolver {
    /// Creates a resolver in a protected daemon-owned repository partition.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>, storage_tenant_id: RecordId) -> Self {
        Self {
            repository,
            storage_tenant_id,
            ids: MonotonicUuidV7Generator::default(),
        }
    }

    /// Enumerates every durable authenticated-tenant mapping at one snapshot-pinned view.
    ///
    /// The result is strictly sorted and unique. Duplicate domain tenant identities, malformed
    /// retained mappings, or a count beyond the caller's explicit bound fail closed so readiness
    /// and recovery cannot silently scan only a prefix of shared-mode tenants.
    pub fn mapped_tenant_ids(
        &self,
        maximum_tenants: usize,
    ) -> Result<Vec<RecordId>, DomainIdentityError> {
        if maximum_tenants == 0 {
            return Err(invalid_mapping());
        }
        let scope = ServiceListScope::new(self.storage_tenant_id.clone(), TENANT_NAMESPACE, None)
            .map_err(map_store_error)?;
        let mut cursor = None;
        let mut tenants = Vec::new();
        loop {
            let remaining = maximum_tenants
                .checked_sub(tenants.len())
                .ok_or_else(invalid_mapping)?;
            if remaining == 0 {
                return Err(invalid_mapping());
            }
            let page = self
                .repository
                .service_list(
                    &ServiceListQuery::new(
                        scope.clone(),
                        remaining.min(TENANT_LIST_PAGE_SIZE),
                        cursor,
                    )
                    .map_err(map_store_error)?,
                    &CancellationToken::default(),
                )
                .map_err(map_store_error)?;
            for record in page.items {
                let subject_digest = ContentDigest::new(record.locator().key().to_owned())
                    .map_err(|_error| invalid_mapping())?;
                parse_strict_json(record.bytes()).map_err(|_error| invalid_mapping())?;
                let mapping: TenantMapping =
                    serde_json::from_slice(record.bytes()).map_err(|_error| invalid_mapping())?;
                mapping.validate(&subject_digest)?;
                tenants.push(mapping.tenant_id);
                if tenants.len() > maximum_tenants {
                    return Err(invalid_mapping());
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        tenants.sort();
        if tenants.windows(2).any(|pair| pair.first() == pair.get(1)) {
            return Err(invalid_mapping());
        }
        Ok(tenants)
    }

    fn allocate_id(&self) -> Result<RecordId, DomainIdentityError> {
        let generated = self
            .ids
            .generate()
            .map_err(|_error| DomainIdentityError::new(DomainIdentityErrorCode::Unavailable))?;
        RecordId::new(generated.to_string()).map_err(|_error| invalid_mapping())
    }

    fn load_tenant(
        &self,
        digest: &ContentDigest,
    ) -> Result<Option<TenantMapping>, DomainIdentityError> {
        let locator = ServiceRecordLocator::new(
            self.storage_tenant_id.clone(),
            TENANT_NAMESPACE,
            digest.as_str(),
        )
        .map_err(map_store_error)?;
        self.repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )
            .map_err(map_store_error)?
            .map(|record| {
                parse_strict_json(record.bytes()).map_err(|_error| invalid_mapping())?;
                let mapping: TenantMapping =
                    serde_json::from_slice(record.bytes()).map_err(|_error| invalid_mapping())?;
                mapping.validate(digest)?;
                Ok(mapping)
            })
            .transpose()
    }

    fn load_principal(
        &self,
        record_key: &ContentDigest,
        tenant_digest: &ContentDigest,
        principal_digest: &ContentDigest,
        tenant_id: &RecordId,
    ) -> Result<Option<PrincipalMapping>, DomainIdentityError> {
        let locator = ServiceRecordLocator::new(
            self.storage_tenant_id.clone(),
            PRINCIPAL_NAMESPACE,
            record_key.as_str(),
        )
        .map_err(map_store_error)?;
        self.repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )
            .map_err(map_store_error)?
            .map(|record| {
                parse_strict_json(record.bytes()).map_err(|_error| invalid_mapping())?;
                let mapping: PrincipalMapping =
                    serde_json::from_slice(record.bytes()).map_err(|_error| invalid_mapping())?;
                mapping.validate(tenant_digest, principal_digest, tenant_id)?;
                Ok(mapping)
            })
            .transpose()
    }

    fn commit_missing(
        &self,
        tenant: Option<&TenantMapping>,
        principal: Option<&PrincipalMapping>,
    ) -> Result<(), DomainIdentityError> {
        let mut writes = Vec::with_capacity(2);
        if let Some(mapping) = tenant {
            writes.push(mapping_write(
                TENANT_NAMESPACE,
                mapping.subject_digest.as_str(),
                mapping,
            )?);
        }
        if let Some(mapping) = principal {
            let key = principal_record_key(
                &mapping.tenant_subject_digest,
                &mapping.principal_subject_digest,
            )?;
            writes.push(mapping_write(PRINCIPAL_NAMESPACE, key.as_str(), mapping)?);
        }
        if writes.is_empty() {
            return Ok(());
        }
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_store_error)?;
        let batch = ServiceBatch::new(self.storage_tenant_id.clone(), writes, response)
            .map_err(map_store_error)?;
        self.repository
            .service_commit(batch, &CancellationToken::default())
            .map(|_receipt| ())
            .map_err(map_store_error)
    }
}

impl DomainIdentityResolver for DurableDomainIdentityResolver {
    fn resolve(
        &self,
        context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, DomainIdentityError> {
        if context.cancellation().is_cancelled() {
            return Err(DomainIdentityError::new(DomainIdentityErrorCode::Cancelled));
        }
        let tenant_digest = subject_digest(
            b"cigar.authenticated-tenant.v1\0",
            context.identity().tenant().as_str(),
        )?;
        let principal_digest = subject_digest(
            b"cigar.authenticated-principal.v1\0",
            context.identity().principal().as_str(),
        )?;
        let principal_key = principal_record_key(&tenant_digest, &principal_digest)?;

        for _attempt in 0..MAX_RESOLUTION_RETRIES {
            if context.cancellation().is_cancelled() {
                return Err(DomainIdentityError::new(DomainIdentityErrorCode::Cancelled));
            }
            let retained_tenant = self.load_tenant(&tenant_digest)?;
            let Some(retained_tenant) = retained_tenant else {
                // Never validate retained principal state against a speculative tenant. If a
                // concurrent process wins after the absent read, this atomic batch conflicts and
                // the next attempt reloads the authoritative tenant first.
                let tenant_id = self.allocate_id()?;
                let new_tenant = TenantMapping {
                    schema_version: TENANT_SCHEMA.to_owned(),
                    subject_digest: tenant_digest.clone(),
                    tenant_id: tenant_id.clone(),
                };
                let new_principal = PrincipalMapping {
                    schema_version: PRINCIPAL_SCHEMA.to_owned(),
                    tenant_subject_digest: tenant_digest.clone(),
                    principal_subject_digest: principal_digest.clone(),
                    tenant_id: tenant_id.clone(),
                    principal_id: self.allocate_id()?,
                };
                match self.commit_missing(Some(&new_tenant), Some(&new_principal)) {
                    Ok(()) => {
                        return Ok(ResolvedDomainIdentity {
                            tenant_id,
                            principal_id: new_principal.principal_id,
                        });
                    }
                    Err(error)
                        if error.code() == DomainIdentityErrorCode::InvalidMapping
                            || error.code() == DomainIdentityErrorCode::Unavailable =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            };
            let tenant_id = retained_tenant.tenant_id;
            let retained_principal = self.load_principal(
                &principal_key,
                &tenant_digest,
                &principal_digest,
                &tenant_id,
            )?;
            if let Some(principal) = retained_principal {
                return Ok(ResolvedDomainIdentity {
                    tenant_id,
                    principal_id: principal.principal_id,
                });
            }
            let new_principal = PrincipalMapping {
                schema_version: PRINCIPAL_SCHEMA.to_owned(),
                tenant_subject_digest: tenant_digest.clone(),
                principal_subject_digest: principal_digest.clone(),
                tenant_id: tenant_id.clone(),
                principal_id: self.allocate_id()?,
            };
            match self.commit_missing(None, Some(&new_principal)) {
                Ok(()) => {
                    return Ok(ResolvedDomainIdentity {
                        tenant_id,
                        principal_id: new_principal.principal_id,
                    });
                }
                Err(error)
                    if error.code() == DomainIdentityErrorCode::InvalidMapping
                        || error.code() == DomainIdentityErrorCode::Unavailable =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(DomainIdentityError::new(
            DomainIdentityErrorCode::Unavailable,
        ))
    }
}

impl fmt::Debug for DurableDomainIdentityResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableDomainIdentityResolver")
            .field("storage_tenant", &"[BOUND]")
            .finish_non_exhaustive()
    }
}

fn mapping_write<T: Serialize>(
    namespace: &str,
    key: &str,
    mapping: &T,
) -> Result<ServiceRecordWrite, DomainIdentityError> {
    let bytes = serde_json::to_vec(mapping).map_err(|_error| invalid_mapping())?;
    ServiceRecordWrite::new(namespace, key, ServiceExpectedVersion::Absent, bytes)
        .map_err(map_store_error)
}

fn subject_digest(domain: &[u8], value: &str) -> Result<ContentDigest, DomainIdentityError> {
    let length = u32::try_from(value.len()).map_err(|_error| invalid_mapping())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
    content_digest(hasher.finalize().as_slice())
}

fn principal_record_key(
    tenant_digest: &ContentDigest,
    principal_digest: &ContentDigest,
) -> Result<ContentDigest, DomainIdentityError> {
    let mut hasher = Sha256::new();
    hasher.update(b"cigar.domain-principal-key.v1\0");
    hasher.update(tenant_digest.as_str().as_bytes());
    hasher.update(principal_digest.as_str().as_bytes());
    content_digest(hasher.finalize().as_slice())
}

fn content_digest(hash: &[u8]) -> Result<ContentDigest, DomainIdentityError> {
    if hash.len() != 32 {
        return Err(invalid_mapping());
    }
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| invalid_mapping())?;
    }
    ContentDigest::new(encoded).map_err(|_error| invalid_mapping())
}

fn map_store_error(error: ServiceError) -> DomainIdentityError {
    let code = match error.code() {
        ServiceErrorCode::Cancelled => DomainIdentityErrorCode::Cancelled,
        ServiceErrorCode::InvalidInput | ServiceErrorCode::LimitExceeded => {
            DomainIdentityErrorCode::InvalidMapping
        }
        ServiceErrorCode::NotFound
        | ServiceErrorCode::RevisionConflict
        | ServiceErrorCode::IdempotencyConflict
        | ServiceErrorCode::CursorScopeMismatch
        | ServiceErrorCode::InjectedAbort
        | ServiceErrorCode::Unavailable => DomainIdentityErrorCode::Unavailable,
    };
    DomainIdentityError::new(code)
}

const fn invalid_mapping() -> DomainIdentityError {
    DomainIdentityError::new(DomainIdentityErrorCode::InvalidMapping)
}

#[cfg(test)]
mod tests {
    use super::{DomainIdentityErrorCode, DomainIdentityResolver, DurableDomainIdentityResolver};
    use cigar_api::{
        AuthenticatedIdentity, CancellationToken as ApiCancellation, OperationId, PrincipalId,
        RequestContext, TenantId, TraceId,
    };
    use cigar_protocol::{RecordId, UtcTimestamp};
    use cigar_store::{InMemoryStore, ServiceRepository, SqliteStore};
    use std::error::Error;
    use std::sync::{Arc, Barrier};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn context(tenant: &str, principal: &str) -> TestResult<RequestContext> {
        Ok(RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new(tenant)?,
                PrincipalId::new(principal)?,
            ),
            OperationId::new("getCapabilities")?,
            UtcTimestamp::parse_rfc3339("2026-07-11T13:00:00Z")?,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            ApiCancellation::new(),
            UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")?,
        )?)
    }

    #[test]
    fn arbitrary_authenticated_names_map_stably_without_cross_scope_aliases() -> TestResult {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let resolver = DurableDomainIdentityResolver::new(repository, record(1)?);
        let first_context = context("project-aabbcc", "uid-501")?;
        let same_tenant_context = context("project-aabbcc", "service-builder")?;
        let other_tenant_context = context("tenant-external", "uid-501")?;

        let first = resolver.resolve(&first_context)?;
        assert_eq!(resolver.resolve(&first_context)?, first);
        let same_tenant = resolver.resolve(&same_tenant_context)?;
        assert_eq!(same_tenant.tenant_id, first.tenant_id);
        assert_ne!(same_tenant.principal_id, first.principal_id);
        let other_tenant = resolver.resolve(&other_tenant_context)?;
        assert_ne!(other_tenant.tenant_id, first.tenant_id);
        assert_ne!(other_tenant.principal_id, first.principal_id);
        let mut expected_tenants = vec![first.tenant_id, other_tenant.tenant_id];
        expected_tenants.sort();
        assert_eq!(resolver.mapped_tenant_ids(2)?, expected_tenants);
        assert_eq!(
            resolver.mapped_tenant_ids(1).map_err(|error| error.code()),
            Err(DomainIdentityErrorCode::InvalidMapping)
        );
        Ok(())
    }

    #[test]
    fn concurrent_first_resolution_has_one_exact_mapping() -> TestResult {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let resolver = Arc::new(DurableDomainIdentityResolver::new(repository, record(2)?));
        let worker_count = 16;
        for round in 0..16 {
            let barrier = Arc::new(Barrier::new(worker_count));
            let mut workers = Vec::new();
            for _worker in 0..worker_count {
                let resolver = Arc::clone(&resolver);
                let barrier = Arc::clone(&barrier);
                let request = context(
                    &format!("project-concurrent-{round}"),
                    &format!("uid-concurrent-{round}"),
                )?;
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    resolver.resolve(&request)
                }));
            }
            let mut resolved = Vec::new();
            for worker in workers {
                resolved.push(
                    worker
                        .join()
                        .map_err(|_panic| "resolver worker panicked")??,
                );
            }
            assert!(resolved.windows(2).all(|pair| pair.first() == pair.get(1)));
        }
        Ok(())
    }

    #[test]
    fn sqlite_restart_retains_mapping_and_cancellation_allocates_nothing() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("domain-identities.sqlite3");
        let storage_tenant = record(3)?;
        let request = context("project-restart", "uid-503")?;
        let expected = {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            DurableDomainIdentityResolver::new(repository, storage_tenant.clone())
                .resolve(&request)?
        };
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let resolver = DurableDomainIdentityResolver::new(repository, storage_tenant);
        assert_eq!(resolver.resolve(&request)?, expected);

        let cancelled = context("project-cancelled", "uid-504")?;
        cancelled.cancellation().cancel();
        assert_eq!(
            resolver.resolve(&cancelled).map_err(|error| error.code()),
            Err(DomainIdentityErrorCode::Cancelled)
        );
        Ok(())
    }
}
