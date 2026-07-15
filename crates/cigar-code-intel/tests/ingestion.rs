//! Atomic ingestion crash and exact-retry integration coverage.

use cigar_catalog::{
    ConnectorContext, DiscoveryPolicy, DiscoveryRequest, GitConnector, IngestionRequest,
    IngestionService, LocalFilesystemConnector, SourceConnector,
};
use cigar_code_intel::{AtomizationProfile, BuiltinAtomizer, BuiltinAtomizerKind, Language};
use cigar_protocol::{
    Classification, EdgeKind, FixedPoint, GovernanceEnvelope, IdempotencyKey, InstructionAuthority,
    Lifecycle, MediaType, QualityEnvelope, RecordId, ScopeEnvelope, SourceUri,
};
use cigar_store::{
    AccessContext, AtomSelector, CancellationToken, InMemoryStore, ReadTransaction, Repository,
    SnapshotSelection, StoreRevision,
};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
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

    let restarted_connector =
        LocalFilesystemConnector::new(root.path(), SourceUri::new("file:///fixture")?)?;
    restarted_connector.discover(
        &DiscoveryRequest {
            root: SourceUri::new("file:///fixture")?,
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
    let no_op = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(1),
            idempotency_key: IdempotencyKey::new("ingest-fixture-no-op")?,
        },
        &restarted_connector,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(no_op.revision, StoreRevision(1));
    assert_eq!(no_op.published_atoms, 0);
    assert_eq!(store.revision()?, StoreRevision(1));

    let replacement = root.path().join("replacement.tmp");
    fs::write(&replacement, b"fn one() { }\nfn two() {}\n")?;
    fs::rename(replacement, root.path().join("lib.rs"))?;
    restarted_connector.refresh(&context())?;
    let refreshed = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(1),
            idempotency_key: IdempotencyKey::new("ingest-fixture-2")?,
        },
        &restarted_connector,
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
fn git_content_edit_preserves_lineage_and_publishes_supersession()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let run = |arguments: &[&str]| -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("git")
            .arg("-C")
            .arg(root.path())
            .args(arguments)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err("git fixture command failed".into())
        }
    };
    run(&["init", "-q"])?;
    run(&["config", "user.email", "fixture@example.invalid"])?;
    run(&["config", "user.name", "Fixture"])?;
    fs::write(root.path().join("README.md"), b"# Before\nOriginal text.\n")?;
    run(&["add", "README.md"])?;
    run(&["commit", "-qm", "before"])?;

    let uri = SourceUri::new("git+file:///lineage-fixture")?;
    let connector = GitConnector::new(root.path(), uri.clone())?;
    let request = DiscoveryRequest {
        root: uri,
        policy: DiscoveryPolicy {
            max_items: 10,
            max_total_bytes: 1_000_000,
            max_record_bytes: 1_000_000,
            excluded_prefixes: Vec::new(),
            allowed_media_types: [MediaType::new("text/markdown")?].into_iter().collect(),
            allow_user_broadening: false,
            follow_internal_symlinks: false,
            secret_patterns: Vec::new(),
        },
        include_overrides: BTreeSet::new(),
    };
    connector.discover(&request, &context())?;
    let first_record = connector
        .snapshot(None, &context())?
        .records
        .first()
        .cloned()
        .ok_or("missing first Git record")?;
    let atomizer = BuiltinAtomizer::new(BuiltinAtomizerKind::Markdown, profile()?)?;
    let store = InMemoryStore::default();
    let access = AccessContext::new(tenant()?, "coding")?;
    IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(0),
            idempotency_key: IdempotencyKey::new("git-lineage-before")?,
        },
        &connector,
        &[&atomizer],
        &context(),
    )?;
    let before = store
        .begin_read(
            access.clone(),
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?
        .query_atoms(AtomSelector::default(), 100, None)?
        .items;
    let first_atom = before.first().cloned().ok_or("missing first atom")?;

    fs::write(root.path().join("README.md"), b"# After\nUpdated text.\n")?;
    run(&["add", "README.md"])?;
    run(&["commit", "-qm", "after"])?;
    connector.refresh(&context())?;
    let second_record = connector
        .snapshot(None, &context())?
        .records
        .first()
        .cloned()
        .ok_or("missing second Git record")?;
    assert_eq!(first_record.record_id, second_record.record_id);
    assert_ne!(first_record.revision, second_record.revision);

    let receipt = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(1),
            idempotency_key: IdempotencyKey::new("git-lineage-after")?,
        },
        &connector,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(receipt.revision, StoreRevision(2));
    let read = store.begin_read(
        access,
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    let after = read.query_atoms(AtomSelector::default(), 100, None)?.items;
    let replacement = after
        .iter()
        .find(|atom| {
            atom.lineage_id == first_atom.lineage_id
                && atom.lifecycle == Lifecycle::Active
                && atom.version_id != first_atom.version_id
        })
        .ok_or("missing active replacement")?;
    let prior = after
        .iter()
        .find(|atom| atom.version_id == first_atom.version_id)
        .ok_or("missing prior atom")?;
    assert_eq!(prior.lifecycle, Lifecycle::Active);
    assert!(prior.superseded_by.is_none());
    assert!(
        read.edges_from(&replacement.version_id, Some(EdgeKind::Supersedes), 10)?
            .iter()
            .any(|edge| edge.to_version == first_atom.version_id)
    );
    Ok(())
}

#[test]
fn empty_source_commits_one_snapshot_then_is_a_restart_safe_no_op()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let uri = SourceUri::new("file:///empty-fixture")?;
    let request = DiscoveryRequest {
        root: uri.clone(),
        policy: DiscoveryPolicy {
            max_items: 10,
            max_total_bytes: 1_000_000,
            max_record_bytes: 1_000_000,
            excluded_prefixes: Vec::new(),
            allowed_media_types: [MediaType::new("text/plain")?].into_iter().collect(),
            allow_user_broadening: false,
            follow_internal_symlinks: false,
            secret_patterns: Vec::new(),
        },
        include_overrides: BTreeSet::new(),
    };
    let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
    connector.discover(&request, &context())?;
    let atomizer = BuiltinAtomizer::new(BuiltinAtomizerKind::Text, profile()?)?;
    let store = InMemoryStore::default();
    let access = AccessContext::new(tenant()?, "coding")?;
    let first = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(0),
            idempotency_key: IdempotencyKey::new("empty-source-first")?,
        },
        &connector,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(first.revision, StoreRevision(1));
    assert_eq!(first.published_atoms, 0);
    assert_eq!(store.revision()?, StoreRevision(1));

    let restarted = LocalFilesystemConnector::new(root.path(), uri)?;
    restarted.discover(&request, &context())?;
    let no_op = IngestionService.ingest(
        &store,
        IngestionRequest {
            access: access.clone(),
            expected_revision: StoreRevision(1),
            idempotency_key: IdempotencyKey::new("empty-source-no-op")?,
        },
        &restarted,
        &[&atomizer],
        &context(),
    )?;
    assert_eq!(no_op.revision, StoreRevision(1));
    assert_eq!(store.revision()?, StoreRevision(1));
    assert_eq!(
        store
            .begin_read(
                access,
                SnapshotSelection::Latest,
                CancellationToken::default(),
            )?
            .outbox()?
            .len(),
        1
    );
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
