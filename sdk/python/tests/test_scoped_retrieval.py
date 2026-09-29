"""Ranking sees scoped inputs first; the real compiler retains final authority."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace

import pytest

from cigar_sdk import LocalContextError, LocalContextGraph
from cigar_sdk.examples.scoped_retrieval import RetrievalDocument, ScopedBM25, ScopedCorpus


def document(node_id, text, source="public", revision="1"):
    return RetrievalDocument(node_id, source, revision, text)


def corpus(records, allowed=None, policy="1"):
    return ScopedCorpus(records, allowed=list(records) if allowed is None else allowed, policy_revision=policy)


def test_callback_never_receives_unselected_records_or_statistics():
    class PrivateMapping(Mapping):
        def __iter__(self):
            raise AssertionError("global inventory enumerated")

        def __len__(self):
            raise AssertionError("global inventory counted")

        def __getitem__(self, key):
            assert key == "allowed", "unauthorized record read"
            return document("allowed", "retry the operation")

    scope = corpus(PrivateMapping(), ["allowed"])

    def callback(query, records, limit):
        assert query == "retry" and limit == 1
        assert tuple(record.id for record in records) == ("allowed",)
        with pytest.raises(FrozenInstanceError):
            records[0].text = "changed"
        return ["allowed"]

    assert scope.rank_with("retry", callback, limit=1) == ["allowed"]
    assert scope.bm25("retry") == ["allowed"]
    assert scope.rank_with("", lambda *_: []) == []


def test_unauthorized_inventory_changes_do_not_affect_identity_or_rank():
    records = {"a": document("a", "retry operation"), "b": document("b", "retry " * 30)}
    first = corpus(records, ["a"])
    records["b"] = document("b", "unrelated private material", "private", "99")
    second = corpus(records, ["a"])
    assert first.identity == second.identity
    assert first.bm25("retry") == second.bm25("retry") == ["a"]


def test_source_text_revision_policy_and_withdrawal_change_identity_without_mutating_snapshot():
    records = {"a": document("a", "retry operation")}
    first = corpus(records)
    identities = {first.identity}
    for change in ({"text": "new text"}, {"source": "elsewhere"}, {"source_revision": "2"}):
        identities.add(corpus({"a": replace(records["a"], **change)}).identity)
    identities.add(corpus(records, policy="2").identity)
    identities.add(corpus({}).identity)
    assert len(identities) == 6
    records.clear()
    assert first.bm25("operation") == ["a"]


def test_reference_ranking_length_normalization_ties_empty_and_unicode():
    records = {
        "long": document("long", "alpha " + "unrelated " * 100),
        "a": document("a", "alpha café Straße"),
        "b": document("b", "alpha café Straße"),
        "empty": document("empty", ""),
    }
    scope = corpus(records, list(reversed(records)))
    index = ScopedBM25(scope)
    assert index.rank("alpha") == ["a", "b", "long"]
    assert index.rank("alpha", limit=1) == ["a"]
    assert index.rank("cafe\u0301 STRASSE") == ["a", "b"]
    assert index.rank("alpha alpha") == index.rank("alpha")
    assert index.rank("missing") == index.rank("") == []
    assert corpus({}).bm25("alpha") == []
    assert corpus({"empty": records["empty"]}).bm25("alpha") == []
    assert corpus(records).identity == scope.identity
    with pytest.raises(TypeError):
        index._postings["private"] = ((0, 1),)


@pytest.mark.parametrize("candidates", [["a", "a"], ["private"], [1], "a", ["a"] * 257])
def test_invalid_external_ranks_fail_before_compilation(candidates):
    scope = corpus({"a": document("a", "alpha")})
    with pytest.raises(ValueError):
        scope.rank_with("alpha", lambda *_: candidates)


@pytest.mark.parametrize("limit", [0, -1, 257, True, 1.5])
def test_bounds_are_checked_before_callback(limit):
    def forbidden(*_):
        raise AssertionError("callback invoked")

    scope = corpus({"a": document("a", "alpha")})
    with pytest.raises(ValueError):
        scope.rank_with("alpha", forbidden, limit=limit)
    with pytest.raises(ValueError):
        scope.bm25("alpha", limit=limit)


def test_scope_and_utf8_limits_are_explicit_and_errors_do_not_echo_text(monkeypatch):
    records = {"a": document("a", "PRIVATE_TEXT")}
    for allowed in [["missing"], ["a", "a"], "a", [1]]:
        with pytest.raises(ValueError):
            corpus(records, allowed)
    for text in ["\ud800PRIVATE", "🦀" * (1024 * 1024 // 4 + 1)]:
        with pytest.raises(ValueError) as caught:
            corpus({"a": document("a", text)})
        assert "PRIVATE" not in str(caught.value)
    monkeypatch.setattr("cigar_sdk.examples.scoped_retrieval._MAX_CORPUS_BYTES", 8)
    with pytest.raises(ValueError, match="corpus exceeds limit"):
        corpus(records)


def test_query_limits_do_not_silently_truncate():
    scope = corpus({"a": document("a", "alpha")})
    for query in ["x" * (16 * 1024 + 1), " ".join(f"term{i}" for i in range(65)), "\ud800"]:
        with pytest.raises(ValueError):
            scope.bm25(query)


def test_real_graph_keeps_authority_if_ranker_output_is_stale_or_bypassed():
    records = {"a": document("a", "authorized evidence"), "b": document("b", "private evidence", "private")}
    scoped = corpus(records, ["a"])
    with LocalContextGraph("scoped-retrieval", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        for record in records.values():
            graph.upsert({"id": record.id, "source": record.source, "text": record.text})
        view = graph.create_view({"id": "agent", "allowed_sources": ["public"], "policy_revision": "1"})
        # Deliberately bypass the recipe validator: core authorization still wins.
        result = view.compile({"query": "evidence", "semantic_candidates": ["b", *scoped.bm25("evidence")]})
        assert {c["node_id"] for b in result["context"]["snapshot"]["blocks"] for c in b["citations"]} == {"a"}
        assert "private evidence" not in result["rendered"]
        graph.replace_source("public", [])
        empty = view.compile({"query": "evidence", "semantic_candidates": scoped.bm25("evidence")})
        assert empty["context"]["snapshot"]["blocks"] == []
        with pytest.raises(LocalContextError, match="RequiredUnavailable"):
            view.compile({"required": ["a"], "semantic_candidates": ["b", "a"]})
