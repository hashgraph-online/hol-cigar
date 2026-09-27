#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::broker::{AgentGrantSpec, AgentLimits, BrokerCredential, SourceOrigin, SourceRevision};
use crate::{AnswerClaim, AnswerDraft, ContextRequest, ContextViewSpec, Utf8ByteCounter};

const LIMIT: usize = 1024 * 1024;
const DOMAIN: &str = "private-recovery-domain";

fn broker() -> ContextBroker {
    ContextBroker::new(DOMAIN, GraphLimits::default(), BrokerLimits::default()).unwrap()
}

fn provenance() -> SourceProvenance {
    SourceProvenance {
        authority: "host".into(),
        upstream_revision: "one".into(),
        observed_at_ms: 1,
        valid_until_ms: None,
        origin: SourceOrigin::Host,
        derived_from: vec![],
    }
}

fn ingest(broker: &mut ContextBroker, source: &str, id: &str, text: &str) {
    let expected = broker.host_source_revision(source).unwrap();
    broker
        .host_replace_source(
            source,
            &expected,
            vec![Document::new(id, source, text)],
            provenance(),
        )
        .unwrap();
}

fn grant(broker: &mut ContextBroker, agent: &str, sources: &[&str]) -> BrokerCredential {
    broker
        .host_grant(AgentGrantSpec {
            view: ContextViewSpec {
                id: agent.into(),
                allowed_sources: sources.iter().map(|s| (*s).into()).collect(),
                writable_sources: sources.iter().map(|s| (*s).into()).collect(),
                policy_revision: "same-policy".into(),
            },
            limits: AgentLimits::default(),
            lease_ms: 60_000,
        })
        .unwrap()
}

fn restore(checkpoint: &BrokerCheckpoint) -> Result<ContextBroker, BrokerError> {
    ContextBroker::from_checkpoint(
        DOMAIN,
        GraphLimits::default(),
        BrokerLimits::default(),
        checkpoint,
    )
}

fn context(
    broker: &mut ContextBroker,
    credential: &BrokerCredential,
) -> crate::broker::BrokerContext {
    broker
        .compile(
            credential,
            &ContextRequest {
                query: "evidence".into(),
                ..ContextRequest::default()
            },
            &Utf8ByteCounter,
        )
        .unwrap()
}

#[test]
fn recovery_preserves_evidence_but_rejects_all_previous_authority() {
    let mut original = broker();
    ingest(&mut original, "public", "fact", "actual evidence");
    ingest(&mut original, "private", "private-fact", "HIDDEN_SOURCE");
    let credential = grant(&mut original, "agent", &["public", "notes"]);
    let before = context(&mut original, &credential);
    let draft = AnswerDraft {
        snapshot_id: before.context.snapshot().id().into(),
        abstain: false,
        claims: vec![AnswerClaim {
            text: "PRIVATE_DRAFT".into(),
            citations: BTreeSet::from(["fact".into()]),
            confidence_bps: Some(9000),
        }],
    };
    let old_keys = draft.review_keys().unwrap();
    original
        .submit_answer(&credential, &before.ticket, draft.clone(), &Utf8ByteCounter)
        .unwrap();
    original
        .propose_source(
            &credential,
            "pending",
            "notes",
            &original.host_source_revision("notes").unwrap(),
            vec![Document::new("unverified", "notes", "PRIVATE_PROPOSAL")],
        )
        .unwrap();
    let old_revision = original.host_source_revision("public").unwrap();
    let checkpoint = original.host_checkpoint(LIMIT).unwrap();
    let bytes = checkpoint.encode(LIMIT).unwrap();
    let encoded = std::str::from_utf8(&bytes).unwrap();
    assert!(!encoded.contains(&credential.secret) && !encoded.contains(&before.ticket));
    assert!(!encoded.contains("PRIVATE_DRAFT") && !encoded.contains("PRIVATE_PROPOSAL"));
    assert!(!format!("{checkpoint:?}").contains("HIDDEN_SOURCE"));
    let mut restored = restore(&BrokerCheckpoint::decode(&bytes, LIMIT).unwrap()).unwrap();
    assert_ne!(restored.epoch(), original.epoch());
    assert_eq!(
        restored.host_source_revision("public").unwrap().version,
        old_revision.version
    );
    assert_eq!(
        restored.host_replace_source("public", &old_revision, vec![], provenance()),
        Err(BrokerError::Conflict)
    );
    assert!(
        restored
            .compile(&credential, &ContextRequest::default(), &Utf8ByteCounter)
            .is_err()
    );
    assert!(
        restored
            .host_submission(&before.ticket, &Utf8ByteCounter)
            .is_err()
    );
    let fresh = grant(&mut restored, "agent", &["public", "notes"]);
    assert!(
        restored
            .revalidate(&fresh, &before.ticket, &Utf8ByteCounter)
            .is_err()
    );
    assert!(restored.proposal_status(&fresh, "pending").is_err());
    let after = context(&mut restored, &fresh);
    assert_eq!(before.rendered, after.rendered);
    assert!(!after.rendered.contains("HIDDEN_SOURCE"));
    let fresh_draft = AnswerDraft {
        snapshot_id: after.context.snapshot().id().into(),
        ..draft
    };
    assert_ne!(old_keys, fresh_draft.review_keys().unwrap());
}

#[test]
fn lineage_is_rebound_and_stale_inputs_remain_stale_after_recovery() {
    let mut original = broker();
    ingest(&mut original, "input", "one", "input evidence");
    let mut derived = provenance();
    derived.derived_from.push(crate::broker::SourceDependency {
        source: "input".into(),
        revision: original.host_source_revision("input").unwrap(),
    });
    original
        .host_replace_source(
            "derived",
            &original.host_source_revision("derived").unwrap(),
            vec![Document::new("two", "derived", "derived evidence")],
            derived,
        )
        .unwrap();
    let mut recovered = restore(&original.host_checkpoint(LIMIT).unwrap()).unwrap();
    let fresh = grant(&mut recovered, "agent", &["derived"]);
    assert!(
        context(&mut recovered, &fresh)
            .rendered
            .contains("derived evidence")
    );
    assert_eq!(
        recovered.host_provenance("derived").unwrap().derived_from[0]
            .revision
            .epoch,
        recovered.epoch()
    );
    ingest(&mut original, "input", "one", "changed input evidence");
    let mut recovered = restore(&original.host_checkpoint(LIMIT).unwrap()).unwrap();
    let fresh = grant(&mut recovered, "agent", &["derived"]);
    assert!(matches!(
        recovered.compile(&fresh, &ContextRequest::default(), &Utf8ByteCounter),
        Err(BrokerError::Stale)
    ));
}

#[test]
fn withdrawal_tombstones_and_dangling_edge_ownership_survive() {
    let mut original = broker();
    ingest(&mut original, "consumer", "a", "dependent evidence");
    ingest(&mut original, "input", "b", "required evidence");
    let expected = BTreeMap::from([(
        "consumer".into(),
        original.host_source_revision("consumer").unwrap(),
    )]);
    original
        .host_set_edge("a", "b", EdgeKind::Requires, true, &expected)
        .unwrap();
    original
        .host_replace_source(
            "input",
            &original.host_source_revision("input").unwrap(),
            vec![],
            provenance(),
        )
        .unwrap();
    let mut restored = restore(&original.host_checkpoint(LIMIT).unwrap()).unwrap();
    let tombstone = restored.host_source_revision("input").unwrap();
    assert_eq!(tombstone.version, 2);
    let owner = grant(&mut restored, "agent", &["consumer", "input"]);
    assert!(
        restored
            .compile(
                &owner,
                &ContextRequest {
                    required: BTreeSet::from(["a".into()]),
                    ..ContextRequest::default()
                },
                &Utf8ByteCounter
            )
            .is_err()
    );
    assert_eq!(
        restored.host_replace_source(
            "replacement",
            &restored.host_source_revision("replacement").unwrap(),
            vec![Document::new("b", "replacement", "forged evidence")],
            provenance()
        ),
        Err(BrokerError::AccessDenied)
    );
    let expected = BTreeMap::from([(
        "consumer".into(),
        restored.host_source_revision("consumer").unwrap(),
    )]);
    restored
        .host_set_edge("a", "b", EdgeKind::Requires, false, &expected)
        .unwrap();
    ingest(&mut restored, "replacement", "b", "new unrelated evidence");
    assert_eq!(restored.host_source_revision("input").unwrap(), tombstone);
}

#[test]
fn contradictions_and_reference_counts_remain_symmetric_after_restore() {
    let mut original = broker();
    ingest(&mut original, "left", "a", "primary evidence");
    ingest(&mut original, "right", "b", "counter evidence");
    let expected = BTreeMap::from([
        (
            "left".into(),
            original.host_source_revision("left").unwrap(),
        ),
        (
            "right".into(),
            original.host_source_revision("right").unwrap(),
        ),
    ]);
    original
        .host_set_edge("b", "a", EdgeKind::Contradicts, true, &expected)
        .unwrap();
    let expected = BTreeMap::from([(
        "left".into(),
        original.host_source_revision("left").unwrap(),
    )]);
    original
        .host_set_edge("a", "b", EdgeKind::Supports, true, &expected)
        .unwrap();
    let mut restored = restore(&original.host_checkpoint(LIMIT).unwrap()).unwrap();
    let owner = grant(&mut restored, "agent", &["left", "right"]);
    let result = restored
        .compile(
            &owner,
            &ContextRequest {
                required: BTreeSet::from(["a".into()]),
                ..ContextRequest::default()
            },
            &Utf8ByteCounter,
        )
        .unwrap();
    assert!(result.rendered.contains("counter evidence"));
    let expected = BTreeMap::from([
        (
            "left".into(),
            restored.host_source_revision("left").unwrap(),
        ),
        (
            "right".into(),
            restored.host_source_revision("right").unwrap(),
        ),
    ]);
    restored
        .host_set_edge("a", "b", EdgeKind::Contradicts, false, &expected)
        .unwrap();
    assert_eq!(restored.edge_nodes["a"].references, 1);
    let expected = BTreeMap::from([(
        "left".into(),
        restored.host_source_revision("left").unwrap(),
    )]);
    restored
        .host_set_edge("a", "b", EdgeKind::Supports, false, &expected)
        .unwrap();
    assert!(restored.edge_nodes.is_empty());
}

#[test]
fn expired_source_cannot_gain_a_new_lifetime_from_recovery() {
    let mut original = broker();
    let mut record = provenance();
    record.valid_until_ms = Some(unix_ms().unwrap() + 5_000);
    original
        .host_replace_source(
            "docs",
            &original.host_source_revision("docs").unwrap(),
            vec![Document::new("one", "docs", "expiring evidence")],
            record,
        )
        .unwrap();
    // Exercise expiration at capture without sleeping or depending on wall-clock scheduling.
    original.sources.get_mut("docs").unwrap().expires = Some(Instant::now());
    let checkpoint = original.host_checkpoint(LIMIT).unwrap();
    let mut recovered = restore(&checkpoint).unwrap();
    let fresh = grant(&mut recovered, "agent", &["docs"]);
    assert!(matches!(
        recovered.compile(&fresh, &ContextRequest::default(), &Utf8ByteCounter),
        Err(BrokerError::Stale)
    ));
    let mut checkpoint = original.host_checkpoint(LIMIT).unwrap();
    checkpoint.envelope.state.captured_at_ms = unix_ms().unwrap() + 60_000;
    assert!(matches!(restore(&checkpoint), Err(BrokerError::Stale)));
}

#[test]
fn source_validity_cannot_extend_beyond_the_saved_remaining_bound() {
    let mut original = broker();
    let mut record = provenance();
    record.valid_until_ms = Some(unix_ms().unwrap() + 60_000);
    original
        .host_replace_source(
            "docs",
            &original.host_source_revision("docs").unwrap(),
            vec![Document::new("one", "docs", "bounded evidence")],
            record,
        )
        .unwrap();
    original.sources.get_mut("docs").unwrap().expires =
        Some(Instant::now() + Duration::from_secs(2));
    let checkpoint = original.host_checkpoint(LIMIT).unwrap();
    let recovered = restore(&checkpoint).unwrap();
    assert!(recovered.sources["docs"].expires.unwrap() <= Instant::now() + Duration::from_secs(2));
}

#[test]
fn codec_enforces_exact_bounds_version_digest_and_canonical_bytes() {
    let mut original = broker();
    ingest(&mut original, "docs", "one", "private evidence");
    let checkpoint = original.host_checkpoint(LIMIT).unwrap();
    let bytes = checkpoint.encode(LIMIT).unwrap();
    assert!(checkpoint.encode(bytes.len()).is_ok());
    assert!(BrokerCheckpoint::decode(&bytes, bytes.len()).is_ok());
    assert!(matches!(
        checkpoint.encode(bytes.len() - 1),
        Err(BrokerError::Quota)
    ));
    assert!(matches!(
        BrokerCheckpoint::decode(&bytes, bytes.len() - 1),
        Err(BrokerError::Quota)
    ));
    assert!(original.host_checkpoint(1).is_err());
    for limit in [0, MAX_BYTES + 1] {
        assert!(checkpoint.encode(limit).is_err());
        assert!(BrokerCheckpoint::decode(&bytes, limit).is_err());
    }
    for changed in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.clone(), b" ".to_vec()].concat(),
        String::from_utf8(bytes.clone())
            .unwrap()
            .replace("private evidence", "altered evidence")
            .into_bytes(),
        String::from_utf8(bytes.clone())
            .unwrap()
            .replace("checkpoint.v1", "checkpoint.v9")
            .into_bytes(),
    ] {
        assert!(BrokerCheckpoint::decode(&changed, LIMIT).is_err());
    }
    assert!(
        ContextBroker::from_checkpoint(
            "different-domain",
            GraphLimits::default(),
            BrokerLimits::default(),
            &checkpoint
        )
        .is_err()
    );
}

#[test]
fn restore_validates_the_current_limits_and_checkpoint_structure() {
    let mut original = broker();
    ingest(&mut original, "left", "a", "first evidence");
    ingest(&mut original, "right", "b", "second evidence");
    let checkpoint = original.host_checkpoint(LIMIT).unwrap();
    assert!(
        ContextBroker::from_checkpoint(
            DOMAIN,
            GraphLimits {
                max_documents: 1,
                ..GraphLimits::default()
            },
            BrokerLimits::default(),
            &checkpoint
        )
        .is_err()
    );
    assert!(
        ContextBroker::from_checkpoint(
            DOMAIN,
            GraphLimits::default(),
            BrokerLimits {
                max_sources: 1,
                ..BrokerLimits::default()
            },
            &checkpoint
        )
        .is_err()
    );
    for mutation in 0..8 {
        let mut checkpoint = original.host_checkpoint(LIMIT).unwrap();
        match mutation {
            0 => checkpoint
                .envelope
                .state
                .documents
                .push(Document::new("a", "left", "duplicate")),
            1 => checkpoint.envelope.state.documents[0].source = "absent".into(),
            2 => checkpoint.envelope.state.sources[0].version = 0,
            3 => checkpoint.envelope.state.sources[0].remaining_ms = Some(5),
            4 => checkpoint.envelope.state.graph_revision = 0,
            5 => {
                checkpoint
                    .envelope
                    .state
                    .edge_owners
                    .insert("extra".into(), "left".into());
            }
            6 => checkpoint.envelope.state.sources[0]
                .provenance
                .derived_from
                .push(crate::broker::SourceDependency {
                    source: "right".into(),
                    revision: SourceRevision {
                        epoch: original.epoch().into(),
                        version: 9,
                    },
                }),
            7 => {
                checkpoint.envelope.state.sources[0]
                    .provenance
                    .derived_from
                    .push(crate::broker::SourceDependency {
                        source: "right".into(),
                        revision: SourceRevision {
                            epoch: original.epoch().into(),
                            version: 1,
                        },
                    });
                checkpoint.envelope.state.sources[1]
                    .provenance
                    .derived_from
                    .push(crate::broker::SourceDependency {
                        source: "left".into(),
                        revision: SourceRevision {
                            epoch: original.epoch().into(),
                            version: 1,
                        },
                    });
            }
            _ => unreachable!(),
        }
        // An untrusted caller can recompute an unauthenticated digest. Structural validation
        // must still reject invalid graph state rather than relying only on that checksum.
        checkpoint.envelope.sha256 = digest(SCHEMA, &checkpoint.envelope.state).unwrap();
        let bytes = checkpoint.encode(LIMIT).unwrap();
        assert!(
            restore(&BrokerCheckpoint::decode(&bytes, LIMIT).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
}
