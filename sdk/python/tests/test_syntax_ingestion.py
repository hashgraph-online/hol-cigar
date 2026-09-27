"""Explicit parser ports preserve source; preprocessing never admits evidence or executes code."""

from __future__ import annotations

import ast
import os
from unittest.mock import patch

import pytest

from cigar_sdk import LocalBrokerError, LocalContextBroker, LocalContextClient, LocalContextError, LocalContextGraph
from cigar_sdk.examples.syntax_ingestion import python_boundaries, run_syntax_ingestion


@pytest.fixture
def graph():
    with LocalContextGraph("syntax-tests", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as graph:
        yield graph


def test_ast_recipe_partitions_complete_decorated_units_and_keeps_preamble(graph):
    text = (
        "# café 🦀\r\n\r\nx = 1; y = 2\r\n\r\n"
        "@decorate(\r\n  name='first',\r\n)\r\n"
        "async def first(\r\n  value,\r\n):\r\n  return value\r\n\r\n"
        "class Second:\r\n  def nested(self):\r\n    return x\r\n"
    )
    document = {"id": "module", "source": "explicit.py", "text": text, "start_line": 50}
    starts = python_boundaries(document)
    assert starts == [54, 62]
    chunks = graph.chunks_at_lines(document, starts)
    assert "".join(chunk["text"] for chunk in chunks) == text
    assert [chunk["start_line"] for chunk in chunks] == [50, 54, 62]
    assert chunks[0]["text"].startswith("# café")
    assert chunks[1]["text"].startswith("@decorate(")
    assert chunks[2]["text"].startswith("class Second:")
    assert [len(ast.parse(chunk["text"]).body) for chunk in chunks] == [2, 1, 1]
    assert graph.stats()["documents"] == 0
    graph.replace_source("explicit.py", chunks)
    graph.replace_source("explicit.py", graph.chunks_at_lines({**document, "text": "x = 3\n"}, []))
    assert graph.stats()["documents"] == 1
    with pytest.raises(LocalContextError, match="RequiredUnavailable"):
        graph.compile({"required": [chunks[1]["id"]]})


@pytest.mark.parametrize("starts", [[0], [1], [4], [3, 2], [3, 3], [2, 3]])
def test_invalid_partitions_do_not_change_graph(graph, starts):
    before = graph.stats()
    with pytest.raises(LocalContextError, match="InvalidInput"):
        graph.chunks_at_lines({"id": "a", "source": "s", "text": "first\n\nthird\n"}, starts)
    assert graph.stats() == before


def test_ast_recipe_rejects_invalid_input_without_emitting_source(capsys):
    for text in ["def PRIVATE_SECRET(:", "x=1\ry=2", "\ud800", "x='\0PRIVATE_SECRET'"]:
        with pytest.raises(LocalContextError, match="InvalidInput") as raised:
            python_boundaries({"id": "a", "source": "PRIVATE_PATH", "text": text})
        assert "PRIVATE" not in str(raised.value)
        assert raised.value.__cause__ is None
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert python_boundaries({"id": "a", "source": "s", "text": "# comments only\n"}) == []
    for text in ["x" * (1024 * 1024 + 1), "🦀" * (1024 * 1024), "x=1\n" * 4097]:
        with pytest.raises(LocalContextError, match="LimitExceeded"):
            python_boundaries({"id": "a", "source": "s", "text": text})


def test_boundary_preprocessing_requires_worker_feature(graph):
    graph._worker_features = tuple(feature for feature in graph._worker_features if feature != "document_boundaries.v1")
    with patch.object(graph, "_call", side_effect=AssertionError("unsupported command sent")):
        with pytest.raises(LocalContextError, match="IncompatibleWorker"):
            graph.chunks_at_lines({"id": "a", "source": "s", "text": "x=1"}, [])


def test_broker_preprocessing_is_host_only_and_never_admits_evidence():
    with LocalContextBroker("syntax-broker", worker_path=os.environ.get("CIGAR_TEST_WORKER")) as broker:
        document = {"id": "code", "source": "code", "text": "first\nsecond\n"}
        revision = broker.source_revision("code")
        chunks = broker.chunks_at_lines(document, [2])
        assert [chunk["id"] for chunk in chunks] == ["code:L1", "code:L2"]
        assert broker.source_revision("code") == revision
        client = LocalContextClient(broker.grant({"id": "a", "allowed_sources": ["code"], "policy_revision": "1"}))
        assert client.compile({"query": "first"})["context"]["snapshot"]["blocks"] == []
        assert not hasattr(client, "chunks_at_lines")
        # A command outside the closed agent protocol closes that connection. The client
        # cannot infer a dispatch outcome from transport loss; native decoding is tested too.
        with pytest.raises(LocalBrokerError, match="Transport") as refused:
            client._call({"op": "chunks_at_lines", "document": document, "starts": [2]})
        assert refused.value.dispatched is None
        assert client.compile({"query": "first"})["context"]["snapshot"]["blocks"] == []
        broker._hello["capabilities"].remove("document_boundaries.v1")
        with patch.object(broker, "_call", side_effect=AssertionError("unsupported command sent")):
            with pytest.raises(LocalBrokerError, match="IncompatibleWorker"):
                broker.chunks_at_lines(document, [2])


def test_complete_offline_syntax_ingestion_example():
    report = run_syntax_ingestion(worker_path=os.environ.get("CIGAR_TEST_WORKER"))
    assert report["status"] == "passed" and report["exact_source_partition"]
    assert report["chunks"] == report["selected_sources"] == 3
    assert report["requires_hol_services"] is False
