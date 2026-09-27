"""Durable broker process restart, authority loss and uncertain-write behavior; offline only."""

import os
from unittest.mock import patch

import pytest

from cigar_sdk import LocalBrokerConnection, LocalBrokerError, LocalContextBroker, LocalContextClient


def provenance(origin="host"):
    return {
        "authority": "host",
        "upstream_revision": "one",
        "observed_at_ms": 1,
        "valid_until_ms": None,
        "origin": origin,
        "derived_from": [],
    }


def options(directory):
    return {"worker_path": os.environ.get("CIGAR_TEST_WORKER"), "storage": {"directory": str(directory)}}


def grant(broker):
    return broker.grant(
        {"id": "agent", "allowed_sources": ["docs", "notes"], "writable_sources": ["notes"], "policy_revision": "same"}
    )


def ingest(broker, text):
    return broker.replace_source(
        "docs", broker.source_revision("docs"), [{"id": "fact", "source": "docs", "text": text}], provenance()
    )


@pytest.mark.skipif(os.name == "nt", reason="persistent directory protection is not implemented for Windows")
def test_restart_after_worker_kill_preserves_admitted_evidence_and_revokes_all_handles(tmp_path):
    opts = options(tmp_path)
    with LocalContextBroker("durable-sdk", **opts) as broker:
        assert broker.capabilities()["storage"] == {"mode": "sqlite-checkpoint.v1", "restored": False}
        ingest(broker, "Retry at most three times.")
        connection = grant(broker)
        client = LocalContextClient(connection)
        proposed = client.propose_source(
            "note-1",
            "notes",
            client.source_revision("notes"),
            [{"id": "note", "source": "notes", "text": "reviewed evidence"}],
        )
        broker.admit_proposal(proposed["proposal_id"], provenance("reviewed_proposal"))
        broker.set_edge("fact", "note", "supports", True, {"docs": broker.source_revision("docs")})
        old = broker.source_revision("docs")
        compiled = client.compile({"query": "retry", "required": ["fact"]})
        draft = {
            "snapshot_id": compiled["context"]["snapshot"]["id"],
            "claims": [{"text": "Retry at most three times.", "citations": ["fact"], "confidence_bps": 9900}],
        }
        identity = client.submit_answer(compiled["ticket"], draft)
        reviews = [
            {"claim_key": key, "verdict": "supported"} for key in broker.submission(compiled["ticket"])["review_keys"]
        ]
        assert broker.check_answer(compiled["ticket"], identity, reviews)["assessment"]["decision"] == "release"
        broker._process.kill()
        broker._process.wait(timeout=5)
    with LocalContextBroker("durable-sdk", **opts) as restored:
        assert restored.capabilities()["storage"]["restored"] is True
        current = restored.source_revision("docs")
        assert current["version"] == old["version"] and current["epoch"] != old["epoch"]
        with pytest.raises(LocalBrokerError, match="Conflict"):
            restored.replace_source("docs", old, [], provenance())
        stale = LocalContextClient(
            LocalBrokerConnection(restored.capabilities()["port"], connection.epoch, connection.secret)
        )
        with pytest.raises(LocalBrokerError):
            stale.compile({"query": "retry"})
        fresh = LocalContextClient(grant(restored))
        with pytest.raises(LocalBrokerError, match="AccessDenied"):
            fresh.revalidate(compiled["ticket"])
        with pytest.raises(LocalBrokerError):
            restored.check_answer(compiled["ticket"], identity, reviews)
        with pytest.raises(LocalBrokerError):
            fresh.proposal_status("note-1")
        result = fresh.compile({"query": "retry", "required": ["fact", "note"]})
        assert "three times" in result["rendered"] and "reviewed evidence" in result["rendered"]
        new_draft = dict(draft, snapshot_id=result["context"]["snapshot"]["id"])
        new_id = fresh.submit_answer(result["ticket"], new_draft)
        with pytest.raises(LocalBrokerError, match="InvalidInput"):
            restored.check_answer(result["ticket"], new_id, reviews)
        restored.replace_source("docs", current, [], provenance())
    with LocalContextBroker("durable-sdk", **opts) as restored:
        fresh = LocalContextClient(grant(restored))
        assert "three times" not in fresh.compile({"query": "retry"})["rendered"]
        assert int(restored.source_revision("docs")["version"]) == int(old["version"]) + 1


@pytest.mark.skipif(os.name == "nt", reason="persistent directory protection is not implemented for Windows")
def test_storage_failure_closes_worker_with_unknown_outcome_and_no_retry(tmp_path):
    opts = options(tmp_path)
    opts["storage"]["max_checkpoint_bytes"] = 4096
    with LocalContextBroker("bounded-store", **opts) as broker:
        old = ingest(broker, "original evidence")["revision"]
        with pytest.raises(LocalBrokerError) as caught:
            ingest(broker, "new evidence" * 1000)
        assert caught.value.code == "Transport" and caught.value.dispatched is None
        assert broker.cleanup_complete
        with pytest.raises(LocalBrokerError, match="Closed"):
            broker.source_revision("docs")
    with LocalContextBroker("bounded-store", **opts) as restored:
        assert restored.source_revision("docs")["version"] == old["version"]
        assert "original evidence" in LocalContextClient(grant(restored)).compile({"query": "evidence"})["rendered"]


@pytest.mark.skipif(os.name == "nt", reason="persistent directory protection is not implemented for Windows")
def test_store_excludes_second_owner_and_rejects_domain_mismatch(tmp_path):
    opts = options(tmp_path)
    with LocalContextBroker("single-owner", **opts) as broker:
        ingest(broker, "durable evidence")
        with pytest.raises(LocalBrokerError) as caught:
            LocalContextBroker("single-owner", **opts)
        assert caught.value.code == "Unavailable" and caught.value.dispatched is False
        assert broker.source_revision("docs")["version"] == "1"
    with pytest.raises(LocalBrokerError, match="Integrity"):
        LocalContextBroker("wrong-domain", **opts)
    with LocalContextBroker("single-owner", **opts) as broker:
        assert broker.source_revision("docs")["version"] == "1"


@pytest.mark.parametrize(
    "storage", [None, {}, {"mode": "memory", "restored": False}, {"mode": "sqlite-checkpoint.v1", "restored": 1}]
)
def test_requested_persistence_cannot_be_silently_ignored(tmp_path, storage):
    with LocalContextBroker("hello", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as broker:
        hello = broker.capabilities()
    hello["storage"] = storage
    with (
        patch.object(LocalContextBroker, "_call", return_value=hello),
        pytest.raises(LocalBrokerError, match="IncompatibleWorker"),
    ):
        LocalContextBroker("hello", **options(tmp_path))
