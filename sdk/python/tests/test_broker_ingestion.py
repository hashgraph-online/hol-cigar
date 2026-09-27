"""Transactional ingestion through the real broker; no provider or external service."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from unittest.mock import patch

import pytest

from cigar_sdk import LocalBrokerError, LocalContextBroker, LocalContextClient


def provenance():
    return {
        "authority": "host",
        "upstream_revision": "one",
        "observed_at_ms": 1,
        "valid_until_ms": None,
        "origin": "host",
        "derived_from": [],
    }


def document(node="fact", text="new evidence"):
    return {"id": node, "source": "docs", "text": text}


def reader(broker):
    return LocalContextClient(broker.grant({"id": "reader", "allowed_sources": ["docs"], "policy_revision": "one"}))


def seed(broker):
    return broker.replace_source("docs", broker.source_revision("docs"), [document(text="old evidence")], provenance())[
        "revision"
    ]


@pytest.fixture
def broker():
    with LocalContextBroker("batch-sdk", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as value:
        yield value
    assert value.cleanup_complete


def test_batched_iterable_has_one_visibility_point_and_preserves_noop_and_withdrawal(broker):
    before = seed(broker)
    client = reader(broker)
    previous = client.compile({"query": "evidence", "required": ["fact"]})
    documents = [document(), document("extra", "additional evidence")]

    def batches():
        for value in documents:
            assert broker.source_revision("docs") == before
            client.revalidate(previous["ticket"])
            context = client.compile({"query": "evidence", "required": ["fact"]})
            assert "old evidence" in context["rendered"] and "new evidence" not in context["rendered"]
            client.forget_ticket(context["ticket"])
            yield [value]
        # The final append is still private, even after the iterable is exhausted.
        assert broker.source_revision("docs") == before
        client.revalidate(previous["ticket"])

    receipt = broker.replace_source_batches("docs", before, batches(), provenance())
    assert receipt == {
        "revision": dict(before, version="2"),
        "inserted": 1,
        "replaced": 1,
        "removed": 0,
        "unchanged": 0,
    }
    with pytest.raises(LocalBrokerError, match="Stale"):
        client.revalidate(previous["ticket"])
    after = client.compile({"query": "evidence", "required": ["fact", "extra"]})
    assert "new evidence" in after["rendered"] and "additional evidence" in after["rendered"]
    ordinary = broker.replace_source("docs", receipt["revision"], documents, provenance())
    assert ordinary["revision"] == receipt["revision"] and ordinary["unchanged"] == 2
    client.revalidate(after["ticket"])
    withdrawal = broker.replace_source_batches("docs", receipt["revision"], iter(()), provenance())
    assert withdrawal["removed"] == 2 and withdrawal["revision"]["version"] == "3"
    assert client.compile({"query": "evidence"})["context"]["snapshot"]["blocks"] == []


def test_low_level_handles_are_host_only_consumed_and_abort_is_harmless(broker):
    before = seed(broker)
    client = reader(broker)
    for name in ("begin_source_replace", "append_source_documents", "commit_source_replace", "abort_source_replace"):
        assert not hasattr(client, name)
    transaction = broker.begin_source_replace("docs", before, provenance())
    assert transaction["epoch"] == before["epoch"]
    assert broker.append_source_documents(transaction, [document()]) == 1
    assert broker.append_source_documents(transaction, [document("extra")]) == 2
    assert broker.source_revision("docs") == before
    assert not broker.abort_source_replace(dict(transaction, epoch="0" * 64))
    assert broker.abort_source_replace(transaction)
    assert not broker.abort_source_replace(transaction)
    with pytest.raises(LocalBrokerError, match="Stale"):
        broker.commit_source_replace(transaction)
    transaction = broker.begin_source_replace("docs", before, provenance())
    broker.append_source_documents(transaction, [document()])
    broker.commit_source_replace(transaction)
    with pytest.raises(LocalBrokerError, match="Stale"):
        broker.commit_source_replace(transaction)


@pytest.mark.parametrize("bad_batch", [[], [document()], [dict(document("second"), source="wrong")]])
def test_invalid_later_batches_abort_without_partial_evidence_or_slot_leak(broker, bad_batch):
    before = seed(broker)
    client = reader(broker)
    for _ in range(5):
        # More than the four staging slots would fail with Quota if cleanup leaked handles.
        with pytest.raises(LocalBrokerError, match="InvalidInput"):
            broker.replace_source_batches("docs", before, iter([[document()], bad_batch]), provenance())
        assert broker.source_revision("docs") == before
    assert "old evidence" in client.compile({"query": "evidence"})["rendered"]


def test_generator_failure_and_abort_failure_preserve_the_exact_original_exception(broker):
    before = seed(broker)
    original = RuntimeError("caller-owned input failure")

    def batches():
        yield [document()]
        raise original

    for _ in range(5):
        with pytest.raises(RuntimeError) as caught:
            broker.replace_source_batches("docs", before, batches(), provenance())
        assert caught.value is original
    with patch.object(broker, "abort_source_replace", side_effect=LocalBrokerError("Closed")):
        with pytest.raises(RuntimeError) as caught:
            broker.replace_source_batches("docs", before, batches(), provenance())
        assert caught.value is original
    assert broker.source_revision("docs") == before


def test_commit_rechecks_cas_and_does_not_retry_or_publish_generator_output(broker):
    before = seed(broker)

    def batches():
        yield [document()]
        broker.replace_source("docs", before, [document(text="concurrent evidence")], provenance())

    with patch.object(broker, "commit_source_replace", wraps=broker.commit_source_replace) as commit:
        with pytest.raises(LocalBrokerError, match="Conflict") as caught:
            broker.replace_source_batches("docs", before, batches(), provenance())
        assert caught.value.dispatched is True
        assert commit.call_count == 1
    assert broker.source_revision("docs")["version"] == "2"
    assert "concurrent evidence" in reader(broker).compile({"query": "evidence"})["rendered"]


def test_capability_refusal_occurs_before_input_iteration_or_any_command(broker):
    before = broker.source_revision("docs")
    hello = broker.capabilities()
    broker._hello = dict(hello, capabilities=[value for value in hello["capabilities"] if value != "source_batches.v1"])
    transaction = {"epoch": before["epoch"], "id": "a" * 64}

    def batches():
        raise AssertionError("unsupported worker must not consume caller input")
        yield []

    with patch.object(broker, "_call", side_effect=AssertionError("unsupported command was sent")):
        for action in (
            lambda: broker.begin_source_replace("docs", before, provenance()),
            lambda: broker.append_source_documents(transaction, [document()]),
            lambda: broker.commit_source_replace(transaction),
            lambda: broker.abort_source_replace(transaction),
            lambda: broker.replace_source_batches("docs", before, batches(), provenance()),
        ):
            with pytest.raises(LocalBrokerError, match="IncompatibleWorker") as caught:
                action()
            assert caught.value.dispatched is False


def test_durable_restart_discards_staging_and_persists_one_receipt_at_commit(tmp_path):
    store = tmp_path / "store"
    options = {
        "worker_path": os.environ.get("CIGAR_TEST_WORKER"),
        "storage": {"directory": str(store), "create_directory": True},
    }
    with LocalContextBroker("batch-sdk", **options) as broker:
        before = seed(broker)
        transaction = broker.begin_source_replace("docs", before, provenance())
        database = store / "broker.sqlite3"
        saved = database.read_bytes()
        broker.append_source_documents(transaction, [document(text="UNCOMMITTED_PRIVATE_INPUT")])
        assert database.read_bytes() == saved
    # The live owner holds an exclusive database lock. Inspect only after it exits.
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as inspection:
        count = inspection.execute("SELECT count(*) FROM broker_journal").fetchone()[0]
    with LocalContextBroker("batch-sdk", **options) as restored:
        assert restored.source_revision("docs")["version"] == before["version"]
        with pytest.raises(LocalBrokerError, match="Stale"):
            restored.commit_source_replace(transaction)
        assert "old evidence" in reader(restored).compile({"query": "evidence"})["rendered"]
        receipt = restored.replace_source_batches(
            "docs", restored.source_revision("docs"), [[document()]], provenance()
        )
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as inspection:
        # One resume record plus one committed replacement; no staging receipts.
        assert inspection.execute("SELECT count(*) FROM broker_journal").fetchone()[0] == count + 2
    with LocalContextBroker("batch-sdk", **options) as restored:
        assert restored.source_revision("docs")["version"] == receipt["revision"]["version"]
        assert "new evidence" in reader(restored).compile({"query": "evidence"})["rendered"]


def test_durable_commit_failure_closes_owner_without_retry_or_masking_unknown_outcome(tmp_path):
    options = {
        "worker_path": os.environ.get("CIGAR_TEST_WORKER"),
        "storage": {"directory": str(tmp_path / "store"), "create_directory": True, "max_checkpoint_bytes": 4096},
    }
    with LocalContextBroker("batch-sdk", **options) as broker:
        before = seed(broker)
        with patch.object(broker, "commit_source_replace", wraps=broker.commit_source_replace) as commit:
            with pytest.raises(LocalBrokerError) as caught:
                broker.replace_source_batches("docs", before, [[document(text="large evidence " * 1000)]], provenance())
            assert caught.value.code == "Transport" and caught.value.dispatched is None
            assert commit.call_count == 1
        assert broker.cleanup_complete
        with pytest.raises(LocalBrokerError, match="Closed"):
            broker.capabilities()
    with LocalContextBroker("batch-sdk", **options) as restored:
        assert restored.source_revision("docs")["version"] == before["version"]
        assert "old evidence" in reader(restored).compile({"query": "evidence"})["rendered"]
