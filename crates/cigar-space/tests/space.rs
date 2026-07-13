//! Concurrency, merge, privacy, event, lease, focus, and federation acceptance tests.

use cigar_protocol::{
    ContentDigest, ContextSpaceId, CoordinationEvent, CoordinationEventKind, ExpectedRevision,
    ExtensionMap, LeaseKind, Overlay, OverlayMutation, RecordId, SchemaVersion, UtcTimestamp,
    VersionId,
};
use cigar_space::{
    AcquireLeaseRequest, ContextSpaceService, CreateSpaceRequest, EventCursor,
    LeaseMutationRequest, ProjectContribution, ProjectLink, ProposedMutation, PublishOutcome,
    PublishRequest, ResolveConflictRequest, ResolverKind, ResourceKey, SpaceError, SpaceHierarchy,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::thread;

fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn space_id() -> Result<ContextSpaceId, Box<dyn std::error::Error>> {
    Ok(ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(VersionId::new(encoded)?)
}

fn content(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(version(value)?.as_str())?)
}

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}

struct Fixture {
    service: ContextSpaceService,
    space_id: ContextSpaceId,
    owner: RecordId,
    project_a: RecordId,
    project_b: RecordId,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let service = ContextSpaceService::new();
    let space_id = space_id()?;
    let owner = record(1)?;
    let project_a = record(2)?;
    let project_b = record(3)?;
    let request = CreateSpaceRequest {
        space_id: space_id.clone(),
        hierarchy: SpaceHierarchy {
            tenant_id: record(4)?,
            workspace_id: record(5)?,
            active_project_id: project_a.clone(),
            branch_id: record(6)?,
            task_id: record(7)?,
            session_id: record(8)?,
        },
        author_id: owner.clone(),
        purpose: "genesis".to_owned(),
        policy_snapshot_digest: content(1)?,
        committed_at: time(0)?,
        event_id: record(9)?,
    };
    let commit = service.create_space(request)?;
    assert_eq!(commit.sequence, 1);
    Ok(Fixture {
        service,
        space_id,
        owner,
        project_a,
        project_b,
    })
}

fn overlay(fixture: &Fixture, overlay_number: u64) -> Result<Overlay, Box<dyn std::error::Error>> {
    Ok(Overlay {
        schema_version: SchemaVersion::new("cigar.overlay", 1)?,
        overlay_id: record(overlay_number)?,
        space_id: fixture.space_id.clone(),
        base_commit_id: fixture.service.head(&fixture.space_id)?.commit_id,
        owner_id: fixture.owner.clone(),
        created_at: time(1)?,
        expires_at: time(59)?,
        mutations: Vec::new(),
        extensions: ExtensionMap::default(),
    })
}

fn publish_request(
    fixture: &Fixture,
    event_number: u64,
) -> Result<PublishRequest, Box<dyn std::error::Error>> {
    Ok(PublishRequest {
        expected_head: ExpectedRevision(fixture.service.head(&fixture.space_id)?.sequence),
        actor_id: fixture.owner.clone(),
        purpose: "publish overlay".to_owned(),
        policy_snapshot_digest: content(1)?,
        committed_at: time(2)?,
        event_id: record(event_number)?,
    })
}

#[test]
fn independent_writers_two_through_sixty_four_have_no_lost_updates()
-> Result<(), Box<dyn std::error::Error>> {
    for writer_count in [2_u64, 8, 64] {
        let fixture = fixture()?;
        let mut prepared = Vec::new();
        for writer in 0..writer_count {
            let overlay = overlay(&fixture, 100 + writer)?;
            let overlay_id = overlay.overlay_id.clone();
            fixture.service.create_overlay(overlay)?;
            fixture.service.propose(
                &fixture.space_id,
                &overlay_id,
                &fixture.owner,
                ProposedMutation {
                    key: ResourceKey::new(format!("artifact/{writer}"))?,
                    mutation: OverlayMutation::Artifact(version(1_000 + writer)?),
                },
            )?;
            prepared.push((overlay_id, 500 + writer));
        }
        let mut handles = Vec::new();
        for (overlay_id, event_number) in prepared {
            let service = fixture.service.clone();
            let space_id = fixture.space_id.clone();
            let owner = fixture.owner.clone();
            let policy = content(1)?;
            let event_id = record(event_number)?;
            handles.push(thread::spawn(move || -> Result<(), SpaceError> {
                loop {
                    let expected = ExpectedRevision(service.head(&space_id)?.sequence);
                    let result = service.publish(
                        &space_id,
                        &overlay_id,
                        PublishRequest {
                            expected_head: expected,
                            actor_id: owner.clone(),
                            purpose: "concurrent publish".to_owned(),
                            policy_snapshot_digest: policy.clone(),
                            committed_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:02Z")
                                .map_err(|_error| SpaceError::InvalidInput)?,
                            event_id: event_id.clone(),
                        },
                    );
                    match result {
                        Ok(PublishOutcome::Published(_commit)) => return Ok(()),
                        Err(SpaceError::StaleRevision) => thread::yield_now(),
                        Ok(PublishOutcome::Deduplicated(_))
                        | Ok(PublishOutcome::Conflicted(_))
                        | Err(_) => return Err(SpaceError::Conflict),
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().map_err(|_panic| "writer panicked")??;
        }
        let view = fixture
            .service
            .view(&fixture.space_id, &fixture.owner, None)?;
        assert_eq!(view.resources.len(), usize::try_from(writer_count)?);
        assert_eq!(view.base.sequence, writer_count + 1);
    }
    Ok(())
}

#[test]
fn stale_revision_and_same_key_conflicts_never_overwrite_silently()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let left = overlay(&fixture, 100)?;
    let right = overlay(&fixture, 101)?;
    let left_id = left.overlay_id.clone();
    let right_id = right.overlay_id.clone();
    fixture.service.create_overlay(left)?;
    fixture.service.create_overlay(right)?;
    for (overlay_id, version_id) in [(&left_id, version(10)?), (&right_id, version(11)?)] {
        fixture.service.propose(
            &fixture.space_id,
            overlay_id,
            &fixture.owner,
            ProposedMutation {
                key: ResourceKey::new("decision/api")?,
                mutation: OverlayMutation::Decision(version_id),
            },
        )?;
    }
    let stale = publish_request(&fixture, 200)?;
    assert!(matches!(
        fixture
            .service
            .publish(&fixture.space_id, &left_id, stale)?,
        PublishOutcome::Published(_)
    ));
    let stale_request = PublishRequest {
        expected_head: ExpectedRevision(1),
        ..publish_request(&fixture, 201)?
    };
    assert_eq!(
        fixture
            .service
            .publish(&fixture.space_id, &right_id, stale_request),
        Err(SpaceError::StaleRevision)
    );
    let outcome = fixture.service.publish(
        &fixture.space_id,
        &right_id,
        publish_request(&fixture, 201)?,
    )?;
    let PublishOutcome::Conflicted(conflicts) = outcome else {
        return Err("expected typed conflict".into());
    };
    assert_eq!(conflicts.len(), 1);
    let conflict = conflicts.first().ok_or("conflict")?;
    assert_eq!(conflict.key.as_str(), "decision/api");
    assert_eq!(conflict.evidence.len(), 2);
    let stored = fixture
        .service
        .list_conflicts(&fixture.space_id, &fixture.owner)?;
    assert_eq!(stored.len(), 1);
    assert!(
        fixture
            .service
            .list_conflicts(&fixture.space_id, &record(999)?)?
            .is_empty()
    );
    let stored = stored.first().ok_or("stored conflict")?;
    let receipt = fixture.service.resolve_conflict(
        &fixture.space_id,
        &stored.conflict_id,
        ResolveConflictRequest {
            expected_head: ExpectedRevision(2),
            actor_id: fixture.owner.clone(),
            resolver: ResolverKind::TypedDecision,
            resolution: OverlayMutation::Decision(version(11)?),
            evidence: stored.conflict.evidence.clone(),
            policy_snapshot_digest: content(1)?,
            resolved_at: time(3)?,
        },
    )?;
    assert_eq!(receipt.conflict_id, stored.conflict_id);
    assert!(
        fixture
            .service
            .list_conflicts(&fixture.space_id, &fixture.owner)?
            .is_empty()
    );
    let resolved = fixture.service.publish(
        &fixture.space_id,
        &right_id,
        PublishRequest {
            expected_head: ExpectedRevision(2),
            actor_id: fixture.owner.clone(),
            purpose: "publish resolved overlay".to_owned(),
            policy_snapshot_digest: content(1)?,
            committed_at: time(4)?,
            event_id: record(202)?,
        },
    )?;
    assert!(matches!(resolved, PublishOutcome::Published(_)));
    assert_eq!(fixture.service.log(&fixture.space_id)?.len(), 3);
    let restored = ContextSpaceService::from_snapshot(&fixture.service.export_snapshot()?)?;
    assert_eq!(restored.log(&fixture.space_id)?.len(), 3);
    let view = fixture
        .service
        .view(&fixture.space_id, &fixture.owner, None)?;
    assert_eq!(view.resources.len(), 1);
    Ok(())
}

#[test]
fn overlay_existence_is_hidden_and_discard_never_changes_history()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let overlay = overlay(&fixture, 100)?;
    let overlay_id = overlay.overlay_id.clone();
    fixture.service.create_overlay(overlay)?;
    let stranger = record(999)?;
    let fake = record(998)?;
    assert_eq!(
        fixture
            .service
            .view(&fixture.space_id, &stranger, Some(&overlay_id)),
        Err(SpaceError::NotFound)
    );
    assert_eq!(
        fixture
            .service
            .view(&fixture.space_id, &stranger, Some(&fake)),
        Err(SpaceError::NotFound)
    );
    fixture
        .service
        .discard_overlay(&fixture.space_id, &overlay_id, &fixture.owner)?;
    assert_eq!(fixture.service.head(&fixture.space_id)?.sequence, 1);
    Ok(())
}

#[test]
fn overlay_focus_fork_and_checkpoint_require_exact_head_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let stale_overlay = overlay(&fixture, 110)?;
    assert_eq!(
        fixture
            .service
            .create_overlay_at_revision(stale_overlay, ExpectedRevision(0)),
        Err(SpaceError::StaleRevision)
    );
    fixture
        .service
        .create_overlay_at_revision(overlay(&fixture, 111)?, ExpectedRevision(1))?;

    let branch_id = record(112)?;
    assert_eq!(
        fixture.service.fork_focus_at_revision(
            &fixture.space_id,
            branch_id.clone(),
            "review",
            false,
            ExpectedRevision(0),
        ),
        Err(SpaceError::StaleRevision)
    );
    fixture.service.fork_focus_at_revision(
        &fixture.space_id,
        branch_id.clone(),
        "review",
        false,
        ExpectedRevision(1),
    )?;
    assert_eq!(
        fixture.service.checkpoint_focus_at_revision(
            &fixture.space_id,
            &branch_id,
            ExpectedRevision(0),
        ),
        Err(SpaceError::StaleRevision)
    );
    let checkpoint = fixture.service.checkpoint_focus_at_revision(
        &fixture.space_id,
        &branch_id,
        ExpectedRevision(1),
    )?;
    assert_eq!(
        checkpoint.checkpoint_commit_id,
        Some(fixture.service.head(&fixture.space_id)?.commit_id)
    );
    Ok(())
}

#[test]
fn event_cursor_reconnect_duplicate_slow_page_priority_and_scope_are_exact()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let events = vec![
        CoordinationEvent {
            event_id: record(301)?,
            kind: CoordinationEventKind::TaskCheckpointed,
            payload_digest: content(301)?,
        },
        CoordinationEvent {
            event_id: record(302)?,
            kind: CoordinationEventKind::PolicySnapshotChanged,
            payload_digest: content(302)?,
        },
    ];
    fixture.service.append_events(
        &fixture.space_id,
        fixture.project_b.clone(),
        publish_request(&fixture, 300)?,
        events,
    )?;
    let only_a = BTreeSet::from([fixture.project_a.clone()]);
    let a_page = fixture
        .service
        .poll_events(&fixture.space_id, &only_a, EventCursor(0), 1)?;
    assert_eq!(a_page.events.len(), 1);
    assert_eq!(a_page.resume_cursor, EventCursor(3));
    assert!(!a_page.has_more);

    let both = BTreeSet::from([fixture.project_a.clone(), fixture.project_b.clone()]);
    let first = fixture
        .service
        .poll_events(&fixture.space_id, &both, EventCursor(0), 1)?;
    let duplicate = fixture
        .service
        .poll_events(&fixture.space_id, &both, EventCursor(0), 1)?;
    assert_eq!(first.events, duplicate.events);
    assert!(first.has_more);
    let rest = fixture
        .service
        .poll_events(&fixture.space_id, &both, first.resume_cursor, 2)?;
    assert_eq!(rest.events.len(), 2);
    assert_eq!(
        rest.events.first().map(|event| event.event.kind),
        Some(CoordinationEventKind::PolicySnapshotChanged)
    );
    assert_eq!(rest.resume_cursor, EventCursor(3));
    assert!(!rest.has_more);
    Ok(())
}

#[test]
fn leases_are_advisory_but_stale_fences_can_never_authorize()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let resource = version(77)?;
    let first = fixture.service.acquire_lease(
        &fixture.space_id,
        AcquireLeaseRequest {
            lease_id: record(400)?,
            resource_id: resource.clone(),
            holder_id: fixture.owner.clone(),
            kind: LeaseKind::Publication,
            acquired_at: time(10)?,
            expires_at: time(20)?,
        },
    )?;
    assert_eq!(first.fencing_token, 1);
    assert_eq!(
        fixture.service.acquire_lease(
            &fixture.space_id,
            AcquireLeaseRequest {
                lease_id: record(401)?,
                resource_id: resource.clone(),
                holder_id: record(44)?,
                kind: LeaseKind::Publication,
                acquired_at: time(11)?,
                expires_at: time(21)?,
            }
        ),
        Err(SpaceError::Conflict)
    );
    let renewed = fixture.service.renew_lease(
        &fixture.space_id,
        &resource,
        LeaseMutationRequest {
            holder_id: fixture.owner.clone(),
            fencing_token: 1,
            expected_revision: ExpectedRevision(1),
            now: time(12)?,
            expires_at: Some(time(30)?),
        },
    )?;
    assert_eq!(renewed.lease.expected_revision, ExpectedRevision(2));
    fixture.service.release_lease(
        &fixture.space_id,
        &resource,
        LeaseMutationRequest {
            holder_id: fixture.owner.clone(),
            fencing_token: 1,
            expected_revision: ExpectedRevision(2),
            now: time(13)?,
            expires_at: None,
        },
    )?;
    assert_eq!(
        fixture
            .service
            .verify_fence(&fixture.space_id, &resource, &fixture.owner, 1, &time(14)?),
        Err(SpaceError::Conflict)
    );
    let second = fixture.service.acquire_lease(
        &fixture.space_id,
        AcquireLeaseRequest {
            lease_id: record(402)?,
            resource_id: resource.clone(),
            holder_id: record(44)?,
            kind: LeaseKind::Publication,
            acquired_at: time(14)?,
            expires_at: time(40)?,
        },
    )?;
    assert_eq!(second.fencing_token, 2);
    assert_eq!(
        fixture
            .service
            .verify_fence(&fixture.space_id, &resource, &fixture.owner, 1, &time(15)?),
        Err(SpaceError::Conflict)
    );
    Ok(())
}

#[test]
fn offline_focus_branches_checkpoint_switch_and_resume_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let first_id = record(500)?;
    let second_id = record(501)?;
    let first =
        fixture
            .service
            .fork_focus(&fixture.space_id, first_id.clone(), "task one", true)?;
    let second =
        fixture
            .service
            .fork_focus(&fixture.space_id, second_id.clone(), "task two", false)?;
    assert_ne!(first.branch_id, second.branch_id);
    let checkpoint = fixture
        .service
        .checkpoint_focus(&fixture.space_id, &first_id)?;
    assert_eq!(checkpoint.checkpoint_commit_id, Some(first.fork_commit_id));
    assert_eq!(
        fixture
            .service
            .switch_focus(&fixture.space_id, &second_id)?,
        second
    );
    let resumed = fixture.service.resume_focus(&fixture.space_id, &first_id)?;
    assert!(!resumed.offline);
    assert_eq!(
        resumed.checkpoint_commit_id,
        checkpoint.checkpoint_commit_id
    );
    Ok(())
}

#[test]
fn project_links_are_directional_hidden_and_contribution_capped()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let preview = fixture.service.link_project(
        &fixture.space_id,
        ProjectLink {
            from_project_id: fixture.project_a.clone(),
            to_project_id: fixture.project_b.clone(),
            relation: " depends   on ".to_owned(),
            contribution_cap_tokens: 10,
        },
        |_project| true,
    )?;
    assert_eq!(preview.relation, "depends on");
    assert_eq!(
        fixture.service.project_link_preview(
            &fixture.space_id,
            &fixture.project_a,
            &fixture.project_b,
            |project| project == &fixture.project_a
        ),
        Err(SpaceError::NotFound)
    );
    let project_c = record(700)?;
    let candidates = vec![
        ProjectContribution {
            project_id: fixture.project_a.clone(),
            version_id: version(1)?,
            tokens: 100,
            mandatory: false,
        },
        ProjectContribution {
            project_id: fixture.project_b.clone(),
            version_id: version(2)?,
            tokens: 6,
            mandatory: false,
        },
        ProjectContribution {
            project_id: fixture.project_b.clone(),
            version_id: version(3)?,
            tokens: 6,
            mandatory: false,
        },
        ProjectContribution {
            project_id: fixture.project_b.clone(),
            version_id: version(4)?,
            tokens: 50,
            mandatory: true,
        },
        ProjectContribution {
            project_id: project_c.clone(),
            version_id: version(5)?,
            tokens: 1,
            mandatory: false,
        },
    ];
    let authorized = BTreeSet::from([
        fixture.project_a.clone(),
        fixture.project_b.clone(),
        project_c,
    ]);
    let selected = fixture.service.cap_project_contributions(
        &fixture.space_id,
        &fixture.project_a,
        &authorized,
        candidates,
    )?;
    assert_eq!(selected.len(), 3);
    assert!(selected.iter().any(|candidate| candidate.mandatory));
    let only_a = BTreeSet::from([fixture.project_a.clone()]);
    let hidden = fixture.service.cap_project_contributions(
        &fixture.space_id,
        &fixture.project_a,
        &only_a,
        selected,
    )?;
    assert_eq!(hidden.len(), 1);
    assert!(
        hidden
            .iter()
            .all(|candidate| candidate.project_id == fixture.project_a)
    );
    Ok(())
}

#[test]
fn complete_snapshot_roundtrip_retains_private_and_coordination_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let private = overlay(&fixture, 800)?;
    let private_id = private.overlay_id.clone();
    fixture.service.create_overlay(private)?;
    fixture.service.propose(
        &fixture.space_id,
        &private_id,
        &fixture.owner,
        ProposedMutation {
            key: ResourceKey::new("private/decision")?,
            mutation: OverlayMutation::Decision(version(800)?),
        },
    )?;

    let published = overlay(&fixture, 801)?;
    let published_id = published.overlay_id.clone();
    fixture.service.create_overlay(published)?;
    fixture.service.propose(
        &fixture.space_id,
        &published_id,
        &fixture.owner,
        ProposedMutation {
            key: ResourceKey::new("shared/artifact")?,
            mutation: OverlayMutation::Artifact(version(801)?),
        },
    )?;
    assert!(matches!(
        fixture.service.publish(
            &fixture.space_id,
            &published_id,
            publish_request(&fixture, 802)?,
        )?,
        PublishOutcome::Published(_)
    ));

    let resource = version(803)?;
    let lease = fixture.service.acquire_lease(
        &fixture.space_id,
        AcquireLeaseRequest {
            lease_id: record(803)?,
            resource_id: resource.clone(),
            holder_id: fixture.owner.clone(),
            kind: LeaseKind::Publication,
            acquired_at: time(3)?,
            expires_at: time(50)?,
        },
    )?;
    let branch_id = record(804)?;
    fixture
        .service
        .fork_focus(&fixture.space_id, branch_id.clone(), "offline review", true)?;
    fixture
        .service
        .checkpoint_focus(&fixture.space_id, &branch_id)?;
    fixture
        .service
        .switch_focus(&fixture.space_id, &branch_id)?;
    fixture.service.link_project(
        &fixture.space_id,
        ProjectLink {
            from_project_id: fixture.project_a.clone(),
            to_project_id: fixture.project_b.clone(),
            relation: "depends on".to_owned(),
            contribution_cap_tokens: 64,
        },
        |_project| true,
    )?;

    let bytes = fixture.service.export_snapshot()?;
    let restored = ContextSpaceService::from_snapshot(&bytes)?;
    assert_eq!(
        restored.head(&fixture.space_id)?,
        fixture.service.head(&fixture.space_id)?
    );
    assert_eq!(
        restored.view(&fixture.space_id, &fixture.owner, Some(&private_id))?,
        fixture
            .service
            .view(&fixture.space_id, &fixture.owner, Some(&private_id))?
    );
    let authorized = BTreeSet::from([fixture.project_a.clone()]);
    assert_eq!(
        restored.poll_events(&fixture.space_id, &authorized, EventCursor(0), 16)?,
        fixture
            .service
            .poll_events(&fixture.space_id, &authorized, EventCursor(0), 16)?
    );
    restored.verify_fence(
        &fixture.space_id,
        &resource,
        &fixture.owner,
        lease.fencing_token,
        &time(4)?,
    )?;
    let branch = restored.resume_focus(&fixture.space_id, &branch_id)?;
    assert_eq!(
        branch.checkpoint_commit_id,
        Some(restored.head(&fixture.space_id)?.commit_id)
    );
    assert!(!branch.offline);
    assert_eq!(
        restored
            .project_link_preview(
                &fixture.space_id,
                &fixture.project_a,
                &fixture.project_b,
                |_project| true,
            )?
            .contribution_cap_tokens,
        64
    );
    Ok(())
}

#[test]
fn snapshot_restore_rejects_semantic_tampering_and_duplicate_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let snapshot = fixture.service.export_snapshot()?;
    let mut value: serde_json::Value = serde_json::from_slice(&snapshot)?;
    let state = value
        .get_mut("spaces")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|spaces| spaces.values_mut().next())
        .ok_or("missing space state")?;
    let sequence = state
        .get_mut("head")
        .and_then(|head| head.get_mut("sequence"))
        .ok_or("missing head sequence")?;
    *sequence = serde_json::Value::from(99_u64);
    assert!(matches!(
        ContextSpaceService::from_snapshot(&serde_json::to_vec(&value)?),
        Err(SpaceError::Integrity)
    ));

    let text = String::from_utf8(snapshot)?;
    let duplicate = text.replacen(
        "{\"schema_version\":",
        "{\"schema_version\":\"cigar.context-space-snapshot.v1\",\"schema_version\":",
        1,
    );
    assert!(matches!(
        ContextSpaceService::from_snapshot(duplicate.as_bytes()),
        Err(SpaceError::Integrity)
    ));
    Ok(())
}
