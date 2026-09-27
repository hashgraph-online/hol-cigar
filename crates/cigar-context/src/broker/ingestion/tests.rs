#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use super::*;
use crate::broker::tests::{broker, compile, ingest, provenance, spec};
use crate::broker::{BrokerLimits, SourceDependency};
use crate::{ContextGraph, ContextRequest, GraphLimits, Utf8ByteCounter};

fn begin(broker: &mut ContextBroker, source: &str) -> SourceTransaction {
    let expected = broker.host_source_revision(source).unwrap();
    broker
        .host_begin_source_replace(source, &expected, provenance("v2"), 60_000)
        .unwrap()
}

#[test]
fn staged_input_has_one_visibility_point_and_preserves_exact_ordinary_output() {
    let mut broker = broker();
    ingest(&mut broker, "docs", "old", "old meaningful evidence");
    let grant = broker.host_grant(spec("reader", &["docs"], &[])).unwrap();
    let old = compile(&mut broker, &grant);
    let revision = broker.host_source_revision("docs").unwrap();
    let transaction = begin(&mut broker, "docs");
    let docs = vec![
        Document::new("z", "docs", "last meaningful evidence"),
        Document::new("a", "docs", "first meaningful evidence"),
    ];
    assert_eq!(
        broker
            .host_append_source_documents(&transaction, vec![docs[0].clone()])
            .unwrap(),
        1
    );
    assert_eq!(
        broker
            .host_append_source_documents(&transaction, vec![docs[1].clone()])
            .unwrap(),
        2
    );
    assert_eq!(broker.host_source_revision("docs").unwrap(), revision);
    assert_eq!(compile(&mut broker, &grant).rendered, old.rendered);
    let receipt = broker.host_commit_source_replace(&transaction).unwrap();
    assert_eq!(
        (receipt.inserted, receipt.replaced, receipt.removed),
        (2, 0, 1)
    );
    assert_eq!(receipt.revision.version, revision.version + 1);
    assert_eq!(broker.staged_bytes(), 0);
    assert_eq!(
        broker.host_commit_source_replace(&transaction),
        Err(BrokerError::Stale)
    );
    let current = compile(&mut broker, &grant);
    assert!(!current.rendered.contains("old meaningful"));
    let same = broker
        .host_replace_source("docs", &receipt.revision, docs.clone(), provenance("v2"))
        .unwrap();
    assert_eq!(same.revision, receipt.revision);
    assert_eq!(same.unchanged, 2);
    assert_eq!(
        serde_json::to_value(&current.context).unwrap(),
        serde_json::to_value(compile(&mut broker, &grant).context).unwrap()
    );

    let mut ordinary = ContextGraph::new("test-private-domain", GraphLimits::default()).unwrap();
    ordinary
        .replace_source(
            "docs",
            vec![Document::new("old", "docs", "old meaningful evidence")],
        )
        .unwrap();
    ordinary.replace_source("docs", docs).unwrap();
    let request = ContextRequest {
        query: "meaningful evidence".into(),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(broker.graph.compile(&request, &Utf8ByteCounter).unwrap()).unwrap(),
        serde_json::to_value(ordinary.compile(&request, &Utf8ByteCounter).unwrap()).unwrap()
    );

    let withdrawal = begin(&mut broker, "docs");
    assert_eq!(
        broker
            .host_commit_source_replace(&withdrawal)
            .unwrap()
            .removed,
        2
    );
    assert!(broker.graph.is_empty());
}

#[test]
fn rejected_batches_keep_prior_staging_and_all_validation_is_shared() {
    let mut broker = broker();
    let tx = begin(&mut broker, "docs");
    broker
        .host_append_source_documents(
            &tx,
            vec![Document::new("one", "docs", "accepted meaningful evidence")],
        )
        .unwrap();
    let retained = broker.staged_bytes();
    let invalid = [
        Vec::new(),
        vec![Document::new("one", "docs", "duplicate")],
        vec![Document::new("two", "wrong-source", "wrong")],
        vec![Document::new("two", "docs", " ")],
        vec![
            Document::new("two", "docs", "valid"),
            Document::new("two", "docs", "duplicate within batch"),
        ],
        vec![Document {
            id: "two".into(),
            source: "docs".into(),
            text: "lines\nmore\n".into(),
            start_line: usize::MAX,
        }],
        vec![Document::new(
            "two",
            "docs",
            "x".repeat(GraphLimits::default().max_document_bytes + 1),
        )],
    ];
    for documents in invalid {
        assert!(broker.host_append_source_documents(&tx, documents).is_err());
        assert_eq!(broker.host_staged_source(&tx).unwrap().2, 1);
        assert_eq!(broker.staged_bytes(), retained);
        assert!(broker.graph.is_empty());
    }
    let receipt = broker.host_commit_source_replace(&tx).unwrap();
    assert_eq!(receipt.inserted, 1);
    assert!(broker.graph.documents.contains_key("one"));
    assert!(!broker.graph.documents.contains_key("two"));
}

#[test]
fn current_cas_derivation_and_ownership_are_rechecked_at_commit() {
    let mut broker = broker();
    let tx = begin(&mut broker, "docs");
    broker
        .host_append_source_documents(&tx, vec![Document::new("draft", "docs", "pending")])
        .unwrap();
    ingest(&mut broker, "docs", "winner", "winning source update");
    assert_eq!(
        broker.host_commit_source_replace(&tx),
        Err(BrokerError::Conflict)
    );
    assert_eq!(broker.host_staged_source(&tx), Err(BrokerError::Stale));
    assert!(broker.graph.documents.contains_key("winner"));
    assert!(!broker.graph.documents.contains_key("draft"));

    let dependency = ingest(&mut broker, "upstream", "up", "original upstream");
    let mut derived = provenance("derived");
    derived.derived_from.push(SourceDependency {
        source: "upstream".into(),
        revision: dependency.revision,
    });
    let expected = broker.host_source_revision("derived").unwrap();
    let tx = broker
        .host_begin_source_replace("derived", &expected, derived, 60_000)
        .unwrap();
    broker
        .host_append_source_documents(
            &tx,
            vec![Document::new("result", "derived", "derived result")],
        )
        .unwrap();
    ingest(&mut broker, "upstream", "up", "changed upstream");
    assert_eq!(
        broker.host_commit_source_replace(&tx),
        Err(BrokerError::Stale)
    );
    assert!(!broker.graph.documents.contains_key("result"));

    let tx = begin(&mut broker, "another");
    broker
        .host_append_source_documents(
            &tx,
            vec![Document::new("free", "another", "intended content")],
        )
        .unwrap();
    ingest(
        &mut broker,
        "different",
        "free",
        "another source acquired the ID",
    );
    assert_eq!(
        broker.host_commit_source_replace(&tx),
        Err(BrokerError::AccessDenied)
    );
    assert_eq!(broker.graph.documents["free"].document.source, "different");
    assert_eq!(broker.staged_bytes(), 0);
}

#[test]
fn expiry_abort_epoch_and_restore_release_staging_without_admission() {
    let mut broker = broker();
    ingest(&mut broker, "docs", "live", "admitted evidence");
    let tx = begin(&mut broker, "docs");
    broker
        .host_append_source_documents(
            &tx,
            vec![Document::new("new", "docs", "STAGED_NOT_ADMITTED")],
        )
        .unwrap();
    let checkpoint = broker.host_checkpoint(1024 * 1024).unwrap();
    let encoded = String::from_utf8(checkpoint.encode(1024 * 1024).unwrap()).unwrap();
    assert!(!encoded.contains("STAGED_NOT_ADMITTED"));
    assert!(!encoded.contains(&tx.id));
    let mut restored = ContextBroker::from_checkpoint(
        "test-private-domain",
        GraphLimits::default(),
        BrokerLimits::default(),
        &checkpoint,
    )
    .unwrap();
    assert_ne!(restored.epoch(), broker.epoch());
    assert_eq!(
        restored.host_commit_source_replace(&tx),
        Err(BrokerError::Stale)
    );
    assert_eq!(restored.staged_bytes(), 0);
    assert!(restored.graph.documents.contains_key("live"));

    let wrong = SourceTransaction {
        epoch: restored.epoch().into(),
        id: tx.id.clone(),
    };
    assert!(!broker.host_abort_source_replace(&wrong));
    broker.staged_sources.get_mut(&tx.id).unwrap().expires = Instant::now();
    assert_eq!(broker.host_staged_source(&tx), Err(BrokerError::Stale));
    assert_eq!(
        broker.host_commit_source_replace(&tx),
        Err(BrokerError::Stale)
    );
    assert_eq!(broker.staged_bytes(), 0);
    let tx = begin(&mut broker, "docs");
    assert!(broker.host_abort_source_replace(&tx));
    assert!(!broker.host_abort_source_replace(&tx));
    assert!(broker.graph.documents.contains_key("live"));
}

#[test]
fn staging_slots_bytes_and_agent_retention_are_bounded_together() {
    let mut broker = broker();
    let handles = (0..4)
        .map(|_| begin(&mut broker, "docs"))
        .collect::<Vec<_>>();
    let expected = broker.host_source_revision("docs").unwrap();
    assert_eq!(
        broker.host_begin_source_replace("docs", &expected, provenance("v2"), 60_000),
        Err(BrokerError::Quota)
    );
    for lease in [0, 300_001] {
        assert_eq!(
            broker.host_begin_source_replace("docs", &expected, provenance("v2"), lease),
            Err(BrokerError::InvalidInput)
        );
    }
    for handle in &handles {
        assert!(broker.host_abort_source_replace(handle));
    }
    assert_eq!(broker.staged_bytes(), 0);

    ingest(&mut broker, "docs", "live", "meaningful evidence");
    let grant = broker.host_grant(spec("reader", &["docs"], &[])).unwrap();
    let ticket = compile(&mut broker, &grant);
    let tx = begin(&mut broker, "docs");
    let total = broker.tickets.values().map(|t| t.bytes).sum::<usize>() + broker.staged_bytes();
    broker.limits.max_retained_bytes = total;
    assert_eq!(
        broker.host_append_source_documents(
            &tx,
            vec![Document::new("new", "docs", "too much retained state")]
        ),
        Err(BrokerError::Quota)
    );
    let request = ContextRequest {
        query: "meaningful evidence".into(),
        ..Default::default()
    };
    assert_eq!(
        broker.compile(&grant, &request, &Utf8ByteCounter).err(),
        Some(BrokerError::Quota)
    );
    assert_eq!(broker.host_staged_source(&tx).unwrap().2, 0);
    assert!(broker.tickets.contains_key(&ticket.ticket));
    assert!(broker.host_abort_source_replace(&tx));
}

#[test]
fn graph_limits_recheck_concurrent_other_source_growth_without_partial_commit() {
    let mut broker = ContextBroker::new(
        "test-private-domain",
        GraphLimits {
            max_documents: 2,
            ..Default::default()
        },
        BrokerLimits::default(),
    )
    .unwrap();
    let tx = begin(&mut broker, "docs");
    broker
        .host_append_source_documents(
            &tx,
            vec![
                Document::new("one", "docs", "one"),
                Document::new("two", "docs", "two"),
            ],
        )
        .unwrap();
    ingest(&mut broker, "other", "outside", "concurrent host evidence");
    assert_eq!(
        broker.host_commit_source_replace(&tx),
        Err(BrokerError::Context(ContextError::LimitExceeded))
    );
    assert_eq!(broker.graph.len(), 1);
    assert!(broker.graph.documents.contains_key("outside"));
    assert_eq!(broker.staged_bytes(), 0);
}
