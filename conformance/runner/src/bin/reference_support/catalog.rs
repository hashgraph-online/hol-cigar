use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_catalog::{
    CatalogErrorCode, ConnectorContext, DependencyInvalidator, InvalidationCause,
    InvalidationWorker, ProjectIdentity, ProjectIdentityInput,
};
use cigar_conformance::CaseOutcome;
use cigar_protocol::{
    ContentDigest, ContextEdge, EdgeKind, ExtensionMap, Lifecycle, RecordId, SchemaVersion,
    VersionId,
};
use cigar_store::{CancellationToken, StoreRevision};
use std::time::{Duration, Instant};

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "catalog_project_invalidation" => project_and_invalidation(input),
        "catalog_cycle_rejection" => cycle_rejection(input),
        _ => Err("unsupported catalog conformance operation".into()),
    }
}

fn project_and_invalidation(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "catalog-project-invalidation-v1")?;
    let primary = ProjectIdentity::derive(project_input("primary")?)?;
    let moved = ProjectIdentity::derive(project_input("primary")?)?;
    let fork = ProjectIdentity::derive(project_input("fork")?)?;
    if primary != moved
        || primary.project_id == fork.project_id
        || primary.normalized_remote() != Some("ssh://example.com/Org/Repo")
    {
        return Err("production project identity invariant failed".into());
    }

    let source = version('a')?;
    let direct = version('b')?;
    let transitive = version('c')?;
    let worker = DependencyInvalidator::new(&[
        edge(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f7810",
            direct.clone(),
            source.clone(),
        )?,
        edge(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f7811",
            transitive.clone(),
            direct.clone(),
        )?,
    ])?;
    let batch = DependencyInvalidator::start(
        source,
        InvalidationCause::SourceChanged,
        None,
        None,
        StoreRevision(7),
    );
    let context = ConnectorContext::new(
        CancellationToken::default(),
        Instant::now() + Duration::from_secs(1),
    );
    let batch = worker.process(batch, 100, &context)?;
    if !batch.frontier.is_empty() || batch.invalidated.len() != 3 {
        return Err("production invalidation closure was incomplete".into());
    }
    let invalidated = batch
        .invalidated
        .iter()
        .map(VersionId::as_str)
        .collect::<Vec<_>>()
        .join(",");
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.catalog.v1",
            &[
                primary.project_id.as_str(),
                primary
                    .normalized_remote()
                    .ok_or("normalized remote missing")?,
                &invalidated,
            ],
        ),
    ))
}

fn cycle_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "catalog-cycle-v1")?;
    let first = version('a')?;
    let second = version('b')?;
    let error = DependencyInvalidator::new(&[
        edge(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f7820",
            first.clone(),
            second.clone(),
        )?,
        edge("01890f47-8e7d-7b42-a1d2-3c4d5e6f7821", second, first)?,
    ])
    .err()
    .ok_or("production catalog accepted a derivation cycle")?;
    if error.code() != CatalogErrorCode::InvalidRecord {
        return Err("production catalog returned the wrong cycle category".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("catalog_invalid_record"),
    ))
}

fn project_input(disambiguator: &str) -> Result<ProjectIdentityInput, Box<dyn std::error::Error>> {
    Ok(ProjectIdentityInput {
        tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        git_remote: Some("git@example.COM:Org/Repo.git".to_owned()),
        root_lineage_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
        disambiguator: disambiguator.to_owned(),
    })
}

fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
    Ok(VersionId::new(format!(
        "1220{}",
        character.to_string().repeat(64)
    ))?)
}

fn edge(
    id: &str,
    from: VersionId,
    to: VersionId,
) -> Result<ContextEdge, Box<dyn std::error::Error>> {
    Ok(ContextEdge {
        schema_version: SchemaVersion::new("cigar.edge", 1)?,
        edge_id: RecordId::new(id)?,
        from_version: from,
        to_version: to,
        kind: EdgeKind::DerivedFrom,
        provenance_digest: ContentDigest::new(format!("1220{}", "f".repeat(64)))?,
        lifecycle: Lifecycle::Active,
        superseded_by: None,
        extensions: ExtensionMap::default(),
    })
}
