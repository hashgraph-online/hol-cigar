"""Actual native selection traces must retain scope, freshness and exact snapshot behavior."""

from __future__ import annotations

import copy
import json
import os
from unittest.mock import patch

import pytest

from cigar_sdk import LocalBrokerError, LocalContextBroker, LocalContextClient, LocalContextError, LocalContextGraph


@pytest.fixture
def graph():
    with LocalContextGraph("explanation", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        yield graph


def test_selected_only_trace_observes_the_actual_root_closure_and_tokenizer(graph):
    graph.upsert({"id": "root", "source": "code", "text": "pub fn authorize_user() {}\n"})
    graph.upsert({"id": "dependency", "source": "rules", "text": "Require permission."})
    graph.upsert({"id": "semantic", "source": "notes", "text": "Independent retrieval lead."})
    graph.upsert({"id": "HIDDEN_ID", "source": "hidden", "text": "authorize_user PRIVATE_TEXT"})
    graph.link("root", "dependency", "requires")
    request = {
        "query": "authorize_user",
        "max_tokens": 1024,
        "allowed": ["root", "dependency", "semantic"],
        "semantic_candidates": ["semantic", "HIDDEN_ID"],
    }
    result = graph.compile(request)
    trace = graph.explain(request, result["snapshot"])
    assert trace["schema"] == "cigar.context-selection-explanation.v1"
    assert trace["snapshot_id"] == result["snapshot"]["id"]
    assert trace["tokenizer"] == result["snapshot"]["tokenizer"]
    assert trace["checked_graph_revision"] == result["snapshot"]["graph_revision"]
    assert len(trace["request_id"]) == 64
    rows = {step["root_id"]: step for step in trace["steps"]}
    assert rows["root"]["added_ids"] == ["dependency", "root"]
    assert rows["root"]["signals"] == ["lexical_match", "declaration_match"]
    assert rows["semantic"]["signals"] == ["semantic_candidate"]
    for value in ["HIDDEN_ID", "PRIVATE_TEXT", "authorize_user", "Require permission."]:
        assert value not in json.dumps(trace)
    assert graph.compile(request) == result
    assert graph.explain(request, result["snapshot"]) == trace


def test_root_explanation_rejects_forgery_and_any_changed_root_graph(graph):
    graph.upsert({"id": "fact", "source": "docs", "text": "evidence"})
    request = {"required": ["fact"]}
    result = graph.compile(request)
    forged = copy.deepcopy(result["snapshot"])
    forged["blocks"][0]["text"] = "FORGED"
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        graph.explain(request, forged)
    graph.upsert({"id": "unrelated", "source": "other", "text": "different"})
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        graph.explain(request, result["snapshot"])


def test_view_explanation_rechecks_scope_without_rebinding_original_snapshot(graph):
    graph.upsert({"id": "fact", "source": "docs", "text": "evidence"})
    a = graph.create_view({"id": "a", "allowed_sources": ["docs"], "policy_revision": "1"})
    b = graph.create_view({"id": "b", "allowed_sources": ["docs"], "policy_revision": "1"})
    result = a.compile({"required": ["fact"]})
    before = a.explain(result["context"])
    assert before["steps"] == [{"root_id": "fact", "added_ids": ["fact"], "signals": ["required"]}]
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        b.explain(result["context"])
    graph.upsert({"id": "secret", "source": "other", "text": "PRIVATE_OTHER"})
    after = a.explain(result["context"])
    assert after["snapshot_id"] == before["snapshot_id"]
    assert after["steps"] == before["steps"]
    assert after["checked_graph_revision"] > before["checked_graph_revision"]
    graph.upsert({"id": "new", "source": "docs", "text": "Unselected new evidence."})
    with pytest.raises(LocalContextError, match="BaseMismatch"):
        a.explain(result["context"])
    graph.revoke_view("a")
    with pytest.raises(LocalContextError, match="RequiredUnavailable"):
        a.explain(result["context"])


def test_absent_capability_refuses_before_dispatch(graph):
    view = graph.create_view({"id": "a", "allowed_sources": [], "policy_revision": "1"})
    result = view.compile({"query": "absent"})
    graph._worker_features = tuple(
        feature for feature in graph._worker_features if feature != "selection_explanation.v1"
    )
    with patch.object(graph, "_call", side_effect=AssertionError("unsupported command was sent")):
        with pytest.raises(LocalContextError, match="IncompatibleWorker"):
            graph.explain({"query": "absent"}, result["context"]["snapshot"])
        with pytest.raises(LocalContextError, match="IncompatibleWorker"):
            view.explain(result["context"])


@pytest.mark.parametrize("change", ["metadata", "revocation", "forgotten_ticket"])
def test_broker_explanation_keeps_current_ticket_authority(change):
    with LocalContextBroker("broker-explain", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as broker:
        documents = [{"id": "fact", "source": "docs", "text": "evidence"}]
        provenance = {
            "authority": "fixture-host",
            "upstream_revision": "1",
            "observed_at_ms": 1,
            "valid_until_ms": None,
            "origin": "host",
            "derived_from": [],
        }
        broker.replace_source("docs", broker.source_revision("docs"), documents, provenance)
        a = LocalContextClient(broker.grant({"id": "a", "allowed_sources": ["docs"], "policy_revision": "1"}))
        b = LocalContextClient(broker.grant({"id": "b", "allowed_sources": ["docs"], "policy_revision": "1"}))
        context = a.compile({"required": ["fact"]})
        trace = a.explain(context["ticket"])
        assert trace["snapshot_id"] == context["context"]["snapshot"]["id"]
        with pytest.raises(LocalBrokerError, match="AccessDenied"):
            b.explain(context["ticket"])
        if change == "metadata":
            broker.replace_source(
                "docs", broker.source_revision("docs"), documents, dict(provenance, upstream_revision="2")
            )
        elif change == "revocation":
            broker.revoke("a")
        else:
            a.forget_ticket(context["ticket"])
        with pytest.raises(LocalBrokerError):
            a.explain(context["ticket"])
