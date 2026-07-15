//! Strict production source registry and built-in connector composition.

use crate::{CatalogContextApplication, ConfiguredSourceRuntime, SourceConfiguration};
use cigar_canon::parse_strict_json;
use cigar_catalog::{
    Atomizer, FILESYSTEM_CONNECTOR_ID, GIT_CONNECTOR_ID, GitConnector, LocalFilesystemConnector,
    SourceConnector, atomizer_registry_digest,
};
use cigar_code_intel::{AtomizationProfile, BuiltinAtomizer};
use cigar_protocol::{ContentDigest, GovernanceEnvelope, QualityEnvelope, RecordId, ScopeEnvelope};
use cigar_store::{CancellationToken, Repository, ServiceRepository};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const SOURCE_REGISTRY_SCHEMA: &str = "cigar.production-source-registry.v1";
const MAX_CONFIGURED_SOURCES: usize = 4_096;

/// Stable content-free source-registry construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionSourceRegistryError {
    /// The strict document, source scope, connector, or atomizer profile was invalid.
    InvalidConfiguration,
    /// A configured root or durable provisioning boundary was unavailable.
    Unavailable,
}

impl fmt::Display for ProductionSourceRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production source registry is unavailable")
    }
}

impl std::error::Error for ProductionSourceRegistryError {}

/// Closed built-in production connector kinds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSourceConnectorKind {
    /// Permission-confined local filesystem snapshots.
    Filesystem,
    /// Immutable committed Git object snapshots.
    Git,
}

/// Exact connector root and closed implementation selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSourceConnectorConfiguration {
    /// Supported built-in connector implementation.
    pub kind: ProductionSourceConnectorKind,
    /// Existing canonical root; symlink roots are rejected.
    pub root_directory: PathBuf,
}

/// Trusted atom governance applied to every record from one configured source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionAtomizationConfiguration {
    /// Sorted non-empty project scope owned by this source.
    pub project_ids: Vec<RecordId>,
    /// Classification, purpose, processor, and instruction gates.
    pub governance: GovernanceEnvelope,
    /// Deterministic source quality metadata.
    pub quality: QualityEnvelope,
    /// Whether protected lexical indexing is policy-eligible.
    pub lexical_enabled: bool,
    /// Whether current policy may permit vector embeddings.
    pub embedding_eligible: bool,
    /// Must be `required_v1`; partial built-in parser sets are unsupported.
    pub atomizer_set: String,
}

impl ProductionAtomizationConfiguration {
    /// Derives the exact ordered built-in atomizer-registry digest required by a production
    /// source configuration for `tenant_id`.
    ///
    /// Configuration authors must use this derivation rather than copying a digest from another
    /// tenant or profile. Startup independently recomputes the value and rejects substitutions.
    pub fn registry_digest(
        &self,
        tenant_id: &RecordId,
    ) -> Result<ContentDigest, ProductionSourceRegistryError> {
        atomization_digest(tenant_id, self)
    }
}

/// One tenant-scoped configured source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSourceEntry {
    /// Exact tenant partition receiving immutable atoms.
    pub tenant_id: RecordId,
    /// Durable connector identity, URI, and discovery policy.
    pub source: SourceConfiguration,
    /// Concrete built-in connector boundary.
    pub connector: ProductionSourceConnectorConfiguration,
    /// Trusted scope and governance for deterministic atomizers.
    pub atomization: ProductionAtomizationConfiguration,
}

/// Complete explicit source registry. An empty `sources` array deliberately disables ingestion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSourceRegistry {
    /// Must be `cigar.production-source-registry.v1`.
    pub schema_version: String,
    /// Sorted unique configured sources; zero is an explicit supported deployment choice.
    pub sources: Vec<ProductionSourceEntry>,
}

impl ProductionSourceRegistry {
    /// Parses strict JSON and validates the closed source configuration surface.
    pub fn from_json(
        bytes: &[u8],
        project_directory: &Path,
    ) -> Result<Self, ProductionSourceRegistryError> {
        parse_strict_json(bytes)
            .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?;
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?;
        registry.validate(project_directory)?;
        Ok(registry)
    }

    fn validate(&self, project_directory: &Path) -> Result<(), ProductionSourceRegistryError> {
        if self.schema_version != SOURCE_REGISTRY_SCHEMA
            || self.sources.len() > MAX_CONFIGURED_SOURCES
            || self.sources.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_some_and(|(left, right)| source_key(left) >= source_key(right))
            })
        {
            return Err(ProductionSourceRegistryError::InvalidConfiguration);
        }
        let project = checked_canonical_directory(project_directory)?;
        let mut roots = BTreeSet::new();
        for entry in &self.sources {
            entry.validate(&project)?;
            let root = checked_canonical_directory(&entry.connector.root_directory)?;
            if !roots.insert((entry.tenant_id.clone(), root)) {
                return Err(ProductionSourceRegistryError::InvalidConfiguration);
            }
        }
        Ok(())
    }

    /// Returns configured tenant identities in source order with duplicates removed.
    #[must_use]
    pub fn configured_tenants(&self) -> Vec<RecordId> {
        let mut tenants: Vec<_> = self
            .sources
            .iter()
            .map(|source| source.tenant_id.clone())
            .collect();
        tenants.sort();
        tenants.dedup();
        tenants
    }

    /// Composes and durably provisions every configured source before listeners may bind.
    pub fn provision<R>(
        &self,
        application: &CatalogContextApplication<R>,
    ) -> Result<(), ProductionSourceRegistryError>
    where
        R: Repository + ServiceRepository + 'static,
    {
        for entry in &self.sources {
            let connector: Arc<dyn SourceConnector> = match entry.connector.kind {
                ProductionSourceConnectorKind::Filesystem => Arc::new(
                    LocalFilesystemConnector::new(
                        &entry.connector.root_directory,
                        entry.source.root.clone(),
                    )
                    .map_err(|_error| ProductionSourceRegistryError::Unavailable)?,
                ),
                ProductionSourceConnectorKind::Git => Arc::new(
                    GitConnector::new(&entry.connector.root_directory, entry.source.root.clone())
                        .map_err(|_error| ProductionSourceRegistryError::Unavailable)?,
                ),
            };
            let mut configured = BuiltinAtomizer::required_v1(atomization_profile(
                &entry.tenant_id,
                &entry.atomization,
            ))
            .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?;
            configured.sort_by_key(|atomizer| {
                let descriptor = atomizer.descriptor();
                (descriptor.id, descriptor.version)
            });
            let atomizers: Vec<Arc<dyn Atomizer>> = configured
                .into_iter()
                .map(|atomizer| Arc::new(atomizer) as Arc<dyn Atomizer>)
                .collect();
            let runtime = Arc::new(
                ConfiguredSourceRuntime::new(entry.source.clone(), connector, atomizers)
                    .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?,
            );
            application
                .provision_source(
                    entry.tenant_id.clone(),
                    runtime,
                    &CancellationToken::default(),
                )
                .map_err(|_error| ProductionSourceRegistryError::Unavailable)?;
        }
        Ok(())
    }
}

impl ProductionSourceEntry {
    fn validate(&self, project: &Path) -> Result<(), ProductionSourceRegistryError> {
        if self.atomization.atomizer_set != "required_v1"
            || self.atomization.project_ids.is_empty()
            || self
                .atomization
                .project_ids
                .windows(2)
                .any(|pair| pair.first() >= pair.get(1))
            || self.atomization.governance.allowed_purposes.is_empty()
            || !strictly_sorted(&self.atomization.governance.allowed_purposes)
            || !strictly_sorted(&self.atomization.governance.processor_constraints)
            || self.atomization.quality.authority == 0
            || self.source.atomization_profile_digest
                != self.atomization.registry_digest(&self.tenant_id)?
        {
            return Err(ProductionSourceRegistryError::InvalidConfiguration);
        }
        let root = checked_canonical_directory(&self.connector.root_directory)?;
        if !root.starts_with(project) {
            return Err(ProductionSourceRegistryError::InvalidConfiguration);
        }
        let (expected_connector, scheme) = match self.connector.kind {
            ProductionSourceConnectorKind::Filesystem => (FILESYSTEM_CONNECTOR_ID, "file"),
            ProductionSourceConnectorKind::Git => (GIT_CONNECTOR_ID, "git+file"),
        };
        if self.source.connector_identity != expected_connector
            || self.source.root.as_str() != canonical_file_uri(scheme, &root)?
        {
            return Err(ProductionSourceRegistryError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn source_key(entry: &ProductionSourceEntry) -> (&RecordId, &RecordId) {
    (&entry.tenant_id, &entry.source.source_id)
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair.first() < pair.get(1))
}

fn atomization_digest(
    tenant_id: &RecordId,
    configuration: &ProductionAtomizationConfiguration,
) -> Result<ContentDigest, ProductionSourceRegistryError> {
    let mut atomizers = BuiltinAtomizer::required_v1(atomization_profile(tenant_id, configuration))
        .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?;
    atomizers.sort_by_key(|atomizer| {
        let descriptor = atomizer.descriptor();
        (descriptor.id, descriptor.version)
    });
    let descriptors: Vec<_> = atomizers.iter().map(Atomizer::descriptor).collect();
    atomizer_registry_digest(&descriptors)
        .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)
}

fn atomization_profile(
    tenant_id: &RecordId,
    configuration: &ProductionAtomizationConfiguration,
) -> AtomizationProfile {
    AtomizationProfile {
        scope: ScopeEnvelope {
            tenant_id: tenant_id.clone(),
            project_ids: configuration.project_ids.clone(),
        },
        governance: configuration.governance.clone(),
        quality: configuration.quality,
        lexical_enabled: configuration.lexical_enabled,
        embedding_eligible: configuration.embedding_eligible,
    }
}

fn checked_canonical_directory(path: &Path) -> Result<PathBuf, ProductionSourceRegistryError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProductionSourceRegistryError::InvalidConfiguration);
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_error| ProductionSourceRegistryError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProductionSourceRegistryError::InvalidConfiguration);
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|_error| ProductionSourceRegistryError::Unavailable)?;
    if canonical != path {
        return Err(ProductionSourceRegistryError::InvalidConfiguration);
    }
    Ok(canonical)
}

fn canonical_file_uri(scheme: &str, path: &Path) -> Result<String, ProductionSourceRegistryError> {
    let value = path
        .to_str()
        .ok_or(ProductionSourceRegistryError::InvalidConfiguration)?;
    let mut uri = format!("{scheme}://");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_error| ProductionSourceRegistryError::InvalidConfiguration)?;
        }
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::{
        FILESYSTEM_CONNECTOR_ID, GIT_CONNECTOR_ID, ProductionAtomizationConfiguration,
        ProductionSourceConnectorConfiguration, ProductionSourceConnectorKind,
        ProductionSourceEntry, ProductionSourceRegistry, ProductionSourceRegistryError,
        SOURCE_REGISTRY_SCHEMA, atomization_digest, canonical_file_uri,
    };
    use crate::{
        AuthorityClock, AuthorityError, BlockingPool, CatalogContextApplication,
        CatalogContextAuthorization, CatalogContextAuthorizationError, CatalogContextAuthorizer,
        DomainIdentityError, DomainIdentityResolver, PinnedContextTokenizerRegistry,
        ResolvedDomainIdentity, SourceConfiguration, SourceDiscoveryPolicyConfiguration,
    };
    use cigar_api::{ApiError, FacadeErrorFactory, RequestContext};
    use cigar_protocol::{
        Classification, ContextContract, ErrorCode, FixedPoint, GovernanceEnvelope,
        InstructionAuthority, MediaType, QualityEnvelope, RecordId, RelativePath, SourceUri,
        UtcTimestamp,
    };
    use cigar_retrieval::InMemoryIndexManager;
    use cigar_store::InMemoryStore;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;

    const TENANT: &str = "01890f47-8e7d-7b42-a1d2-000000000001";
    const PRINCIPAL: &str = "01890f47-8e7d-7b42-a1d2-000000000002";
    const PROJECT: &str = "01890f47-8e7d-7b42-a1d2-000000000003";
    const SOURCE: &str = "01890f47-8e7d-7b42-a1d2-000000000004";
    const CORRELATION: &str = "01890f47-8e7d-7b42-a1d2-000000000005";

    struct FixedIdentity {
        tenant: RecordId,
        principal: RecordId,
    }

    impl DomainIdentityResolver for FixedIdentity {
        fn resolve(
            &self,
            _context: &RequestContext,
        ) -> Result<ResolvedDomainIdentity, DomainIdentityError> {
            Ok(ResolvedDomainIdentity {
                tenant_id: self.tenant.clone(),
                principal_id: self.principal.clone(),
            })
        }
    }

    struct DenyingAuthorizer;

    impl CatalogContextAuthorizer for DenyingAuthorizer {
        fn authorize_catalog(
            &self,
            _identity: &ResolvedDomainIdentity,
            _observed_at: UtcTimestamp,
        ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
            Err(CatalogContextAuthorizationError::Denied)
        }

        fn authorize_contract(
            &self,
            _identity: &ResolvedDomainIdentity,
            _contract: &ContextContract,
            _observed_at: UtcTimestamp,
        ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
            Err(CatalogContextAuthorizationError::Denied)
        }
    }

    struct FixedClock(UtcTimestamp);

    impl AuthorityClock for FixedClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(self.0)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.0.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    struct Errors(RecordId);

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: ErrorCode) -> ApiError {
            ApiError::new(code, self.0.clone())
        }
    }

    fn entry(root: &Path, source: &str) -> Result<ProductionSourceEntry, Box<dyn Error>> {
        let atomization = ProductionAtomizationConfiguration {
            project_ids: vec![RecordId::new(PROJECT)?],
            governance: GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            },
            quality: QualityEnvelope {
                confidence: FixedPoint::new(FixedPoint::ONE)?,
                coverage: FixedPoint::new(FixedPoint::ONE)?,
                authority: 1,
            },
            lexical_enabled: true,
            embedding_eligible: false,
            atomizer_set: "required_v1".to_owned(),
        };
        Ok(ProductionSourceEntry {
            tenant_id: RecordId::new(TENANT)?,
            source: SourceConfiguration {
                schema_version: "cigar.source-configuration.v1".to_owned(),
                source_id: RecordId::new(source)?,
                root: SourceUri::new(canonical_file_uri("file", root)?)?,
                connector_identity: FILESYSTEM_CONNECTOR_ID.to_owned(),
                atomization_profile_digest: atomization_digest(
                    &RecordId::new(TENANT)?,
                    &atomization,
                )?,
                discovery_policy: SourceDiscoveryPolicyConfiguration {
                    max_items: 1_000,
                    max_total_bytes: 16 * 1024 * 1024,
                    max_record_bytes: 1024 * 1024,
                    excluded_prefixes: vec![RelativePath::new(b".git".to_vec())?],
                    allowed_media_types: BTreeSet::from([MediaType::new("text/plain")?]),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
            },
            connector: ProductionSourceConnectorConfiguration {
                kind: ProductionSourceConnectorKind::Filesystem,
                root_directory: root.to_path_buf(),
            },
            atomization,
        })
    }

    fn git_entry(root: &Path, source: &str) -> Result<ProductionSourceEntry, Box<dyn Error>> {
        let mut entry = entry(root, source)?;
        entry.source.connector_identity = GIT_CONNECTOR_ID.to_owned();
        entry.source.root = SourceUri::new(canonical_file_uri("git+file", root)?)?;
        entry.connector.kind = ProductionSourceConnectorKind::Git;
        Ok(entry)
    }

    fn application(
        repository: Arc<InMemoryStore>,
    ) -> Result<CatalogContextApplication<InMemoryStore>, Box<dyn Error>> {
        let now = UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")?;
        Ok(CatalogContextApplication::new(
            repository,
            Arc::new(FixedIdentity {
                tenant: RecordId::new(TENANT)?,
                principal: RecordId::new(PRINCIPAL)?,
            }),
            Arc::new(DenyingAuthorizer),
            Arc::new(InMemoryIndexManager::default()),
            Arc::new(PinnedContextTokenizerRegistry::default()),
            Arc::new(BlockingPool::new(2, 8)?),
            Arc::new(FixedClock(now)),
            Arc::new(Errors(RecordId::new(CORRELATION)?)),
        ))
    }

    #[test]
    fn strict_empty_unknown_kind_order_and_root_escape_are_enforced() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let project = directory.path().join("project");
        let outside = directory.path().join("outside");
        std::fs::create_dir_all(&project)?;
        std::fs::create_dir_all(&outside)?;
        let project = std::fs::canonicalize(project)?;
        let outside = std::fs::canonicalize(outside)?;

        let empty = format!(r#"{{"schema_version":"{SOURCE_REGISTRY_SCHEMA}","sources":[]}}"#);
        let parsed = ProductionSourceRegistry::from_json(empty.as_bytes(), &project)?;
        assert!(parsed.sources.is_empty());

        let duplicate = format!(
            r#"{{"schema_version":"{SOURCE_REGISTRY_SCHEMA}","schema_version":"{SOURCE_REGISTRY_SCHEMA}","sources":[]}}"#
        );
        assert_eq!(
            ProductionSourceRegistry::from_json(duplicate.as_bytes(), &project),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );

        let registry = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![entry(&project, SOURCE)?],
        };
        let mut unknown: serde_json::Value = serde_json::to_value(&registry)?;
        *unknown
            .pointer_mut("/sources/0/connector/kind")
            .ok_or("missing serialized connector kind")? = serde_json::json!("remote_magic");
        assert_eq!(
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&unknown)?, &project),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );

        let escaped = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![entry(&outside, SOURCE)?],
        };
        assert_eq!(
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&escaped)?, &project),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );

        let later_source = "01890f47-8e7d-7b42-a1d2-000000000006";
        let reversed = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![entry(&project, later_source)?, entry(&project, SOURCE)?],
        };
        assert_eq!(
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&reversed)?, &project),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );

        let duplicate_root = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![entry(&project, SOURCE)?, entry(&project, later_source)?],
        };
        assert_eq!(
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&duplicate_root)?, &project),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );

        let mut mismatched_profile = entry(&project, SOURCE)?;
        mismatched_profile.atomization.lexical_enabled = false;
        let mismatched_profile = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![mismatched_profile],
        };
        assert_eq!(
            ProductionSourceRegistry::from_json(
                &serde_json::to_vec(&mismatched_profile)?,
                &project,
            ),
            Err(ProductionSourceRegistryError::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn filesystem_source_provisions_idempotently_across_application_restart()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let project = directory.path().join("project");
        std::fs::create_dir_all(&project)?;
        let project = std::fs::canonicalize(project)?;
        std::fs::write(project.join("README.txt"), "durable source fixture")?;
        let registry = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![entry(&project, SOURCE)?],
        };
        let parsed =
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&registry)?, &project)?;
        let repository = Arc::new(InMemoryStore::default());
        parsed.provision(&application(Arc::clone(&repository))?)?;
        parsed.provision(&application(repository)?)?;
        assert_eq!(parsed.configured_tenants(), vec![RecordId::new(TENANT)?]);
        Ok(())
    }

    #[test]
    fn committed_git_source_uses_the_closed_builtin_connector_and_provisions()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let project = directory.path().join("project");
        let repository_root = project.join("repository");
        std::fs::create_dir_all(&repository_root)?;
        let run = |arguments: &[&str]| -> Result<(), Box<dyn Error>> {
            let status = Command::new("git")
                .arg("-C")
                .arg(&repository_root)
                .args(arguments)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err("Git fixture command failed".into())
            }
        };
        run(&["init", "-q"])?;
        run(&["config", "user.email", "fixture@example.invalid"])?;
        run(&["config", "user.name", "Fixture"])?;
        std::fs::write(
            repository_root.join("README.txt"),
            "committed source fixture",
        )?;
        run(&["add", "README.txt"])?;
        run(&["commit", "-qm", "fixture"])?;

        let project = std::fs::canonicalize(project)?;
        let repository_root = std::fs::canonicalize(repository_root)?;
        let registry = ProductionSourceRegistry {
            schema_version: SOURCE_REGISTRY_SCHEMA.to_owned(),
            sources: vec![git_entry(&repository_root, SOURCE)?],
        };
        let parsed =
            ProductionSourceRegistry::from_json(&serde_json::to_vec(&registry)?, &project)?;
        parsed.provision(&application(Arc::new(InMemoryStore::default()))?)?;
        assert_eq!(
            parsed
                .sources
                .first()
                .ok_or("missing provisioned Git source")?
                .connector
                .kind,
            ProductionSourceConnectorKind::Git
        );
        Ok(())
    }
}
