//! Source snapshots, immutable atom publication, provenance, lifecycle, and invalidation.

mod atom_operations;
mod connector;
mod filesystem;
mod git;
mod ignore;
mod ingestion;
mod invalidation;
mod lifecycle;
mod project;
mod secret;

pub use atom_operations::{AtomBatch, CatalogAtomService, MAX_ATOM_BATCH_ITEMS, TombstoneReceipt};
pub use connector::{
    AtomizationOutput, AtomizationRequest, Atomizer, AtomizerDescriptor, AtomizerInvalidation,
    BoundedBytes, ByteRange, CatalogError, CatalogErrorCode, ChangeKind, ChangeWatermark,
    ConnectorContext, DiscoveryDisposition, DiscoveryEntry, DiscoveryPlan, DiscoveryPolicy,
    DiscoveryReason, DiscoveryRequest, FILESYSTEM_CONNECTOR_ID, GIT_CONNECTOR_ID, IngestionReceipt,
    InvalidationBatch, InvalidationCause, InvalidationWorker, MAX_ATOMIZATION_BYTES,
    MAX_CONNECTOR_ITEMS, MAX_CONNECTOR_READ_BYTES, MAX_CONNECTOR_SNAPSHOT_BYTES,
    MAX_SECRET_PATTERNS, SourceChange, SourceConnector, SourceConnectorDescriptor, SourceHealth,
    SourceHealthState, SourceRecord, SourceSnapshotBatch, atomizer_configuration_digest,
    atomizer_registry_digest,
};
pub use filesystem::LocalFilesystemConnector;
pub use git::GitConnector;
pub use ingestion::{IngestionRequest, IngestionService};
pub use invalidation::DependencyInvalidator;
pub use lifecycle::{BitemporalCatalogView, LifecyclePlanner};
pub use project::{ProjectIdentity, ProjectIdentityInput};
pub use secret::{
    MAX_SECRET_FINDINGS, MAX_SECRET_SCAN_BYTES, SecretFinding, SecretKind, SecretScan,
    blinded_secret_fingerprint, scan_secrets, scan_secrets_with_patterns,
};
