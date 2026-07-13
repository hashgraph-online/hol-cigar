//! Atomic ingestion crash and exact-retry integration coverage.

use cigar_catalog::{
    ConnectorContext, DiscoveryPolicy, DiscoveryRequest, IngestionRequest, IngestionService,
    LocalFilesystemConnector, SourceConnector,
};
use cigar_code_intel::{AtomizationProfile, BuiltinAtomizer, BuiltinAtomizerKind, Language};
use cigar_protocol::{
    Classification, EdgeKind, FixedPoint, GovernanceEnvelope, IdempotencyKey, InstructionAuthority,
    MediaType, QualityEnvelope, RecordId, ScopeEnvelope, SourceUri,
};
use cigar_store::{
    AccessContext, AtomSelector, CancellationToken, InMemoryStore, ReadTransaction, Repository,
    SnapshotSelection, StoreRevision,
};
use std::collections::BTreeSet;
use std::fs;
use std::time::{Duration, Instant};

fn context() -> ConnectorContext {
    ConnectorContext::new(
        CancellationToken::default(),
        Instant::now() + Duration::from_secs(10),
    )
}

fn tenant() -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
}

fn profile() -> Result<AtomizationProfile, Box<dyn std::error::Error>> {
    Ok(AtomizationProfile {
        scope: ScopeEnvelope {
            tenant_id: tenant()?,
            project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?],
        },
        governance: GovernanceEnvelope {
            classification: Classification::Internal,
            allowed_purposes: vec!["coding".to_owned()],
            processor_constraints: Vec::new(),
            instruction_authority: InstructionAuthority::Data,
        },
        quality: QualityEnvelope {
            confidence: FixedPoint::new(1_000_000)?,
            coverage: FixedPoint::new(1_000_000)?,
            authority: 1,
        },
        lexical_enabled: true,
        embedding_eligible: false,
    })
}

#[test]
fn interrupted_ingestion_is_invisible_and_exact_retry_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("lib.rs"), b"fn one() {}\nfn two() {}\n")?;
    let uri = SourceUri::new("file:///fixture")?;
    let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
    connector.discover(
        &DiscoveryRequest {
            root: uri,
            policy: DiscoveryPolicy {
                max_items: 10,
                max_total_bytes: 1_000_000,
                max_record_bytes: 1_000_000,
                excluded_prefixes: Vec::new(),
                allowed_media_types: [MediaType::new("text/x-rust")?].into_iter().collect(),
                allow_user_broadening: false,
                follow_internal_symlinks: false,
                secret_patterns: Vec::new(),
            },
            include_overrides: BTreeSet::new(),
        },
        &context(),
    )?;
    let atomizer = BuiltinAtomizer::new(BuiltinAtomizerKind::Code(Language::Rust), profile()?)?;
    let store = InMemoryStore::default();
    let access = AccessContext::new(tenant()?, "coding")?;
    let request = IngestionRequest {
        access: access.clone(),
        expected_revision: StoreRevision(0),
        idempotency_key: IdempotencyKey::new("ingest-fixture-1")?,
    };
    store.fail_next_commit();
    assert!(
        IngestionService
            .ingest(
                &store,
                request.clone(),
                &connector,
                &[&atomizer],
                &context(),
            )
            .is_err()
    );
    assert_eq!(store.revision()?, StoreRevision(0));
    let before = store.begin_read(
        access.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    assert!(
        before
            .query_atoms(AtomSelector::default(), 100, None)?
            .items
            .is_empty()
    );

    let committed = IngestionService.ingest(
        &store,
        request.clone(),
        &connector,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(committed.revision, StoreRevision(1));
    assert_eq!(committed.published_atoms, 3);
    let replayed =
        IngestionService.ingest(&store, request, &connector, &[&atomizer], &context())?;
    assert_eq!(replayed.revision, StoreRevision(1));
    assert_eq!(replayed.publication_digest, committed.publication_digest);
    assert_eq!(store.revision()?, StoreRevision(1));
    assert_eq!(
        store
            .begin_read(
                access.clone(),
                SnapshotSelection::Latest,
                CancellationToken::default(),
            )?
            .outbox()?
            .len(),
        1
    );

    fs::write(root.path().join("lib.rs"), b"fn one() { }\nfn two() {}\n")?;
    connector.refresh(&context())?;
    let refreshed = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(1),
            idempotency_key: IdempotencyKey::new("ingest-fixture-2")?,
        },
        &connector,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(refreshed.revision, StoreRevision(2));
    assert!(refreshed.tombstoned_atoms >= 1);
    let after = store.begin_read(
        access,
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    let atoms = after.query_atoms(AtomSelector::default(), 100, None)?.items;
    let mut supersession_edges = 0_usize;
    for atom in &atoms {
        supersession_edges += after
            .edges_from(&atom.version_id, Some(EdgeKind::Supersedes), 100)?
            .len();
        for edge in after.edges_from(&atom.version_id, Some(EdgeKind::DerivedFrom), 100)? {
            assert!(after.get_atom(&edge.to_version)?.is_some());
        }
    }
    assert!(supersession_edges >= 1);
    assert_eq!(after.outbox()?.len(), 2);
    Ok(())
}

#[test]
fn sustained_small_atom_ingestion_meets_gate() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CIGAR_PERFORMANCE_GATES").ok().as_deref() != Some("1") {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let bytes = vec![b'x'; 8 * 1_024 * 1_024];
    fs::write(root.path().join("bulk.txt"), bytes)?;
    let uri = SourceUri::new("file:///throughput-fixture")?;
    let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
    connector.discover(
        &DiscoveryRequest {
            root: uri,
            policy: DiscoveryPolicy {
                max_items: 10,
                max_total_bytes: 16 * 1_024 * 1_024,
                max_record_bytes: 16 * 1_024 * 1_024,
                excluded_prefixes: Vec::new(),
                allowed_media_types: [MediaType::new("text/plain")?].into_iter().collect(),
                allow_user_broadening: false,
                follow_internal_symlinks: false,
                secret_patterns: Vec::new(),
            },
            include_overrides: BTreeSet::new(),
        },
        &context(),
    )?;
    let atomizer = BuiltinAtomizer::new(BuiltinAtomizerKind::Text, profile()?)?;
    let store = InMemoryStore::default();
    let started = Instant::now();
    let receipt = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: AccessContext::new(tenant()?, "coding")?,
            expected_revision: StoreRevision(0),
            idempotency_key: IdempotencyKey::new("throughput-fixture-1")?,
        },
        &connector,
        &[&atomizer],
        &context(),
    )?;
    let elapsed = started.elapsed();
    let throughput = receipt.published_atoms as f64 / elapsed.as_secs_f64();
    println!(
        "WP05_INGESTION atoms={} elapsed_ms={} atoms_per_second={throughput:.2}",
        receipt.published_atoms,
        elapsed.as_millis()
    );
    assert!(receipt.published_atoms >= 500);
    assert!(throughput >= 250.0);
    Ok(())
}
