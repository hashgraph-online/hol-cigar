"""Offline Python AST adapter example. Parses explicit text; never reads files or executes it.

This recipe preserves top-level syntax units, not runtime dependency completeness.
The host still chooses authorized inputs, dependency edges and source provenance.
"""

from __future__ import annotations

import ast
import json
import warnings
from pathlib import Path

from cigar_sdk.context import LocalContextError, LocalContextGraph
from cigar_sdk.context_types import LocalDocument

_MAX_PARSE_BYTES = 1024 * 1024


def python_boundaries(document: LocalDocument) -> list[int]:
    """A bounded example parser port: absolute starts of subsequent top-level Python units.

    Preserve decorators and the initial preamble; join same-line statements. Only LF/CRLF
    source is supported because the native citation line convention uses LF boundaries.
    This uses the host Python grammar and grants no source or execution authority.
    """
    text = document.get("text")
    start = document.get("start_line", 1)
    if not isinstance(text, str) or type(start) is not int or start < 1 or start > 2**64 - 1:
        raise LocalContextError("InvalidInput")
    if len(text) > _MAX_PARSE_BYTES:
        raise LocalContextError("LimitExceeded")
    try:
        if len(text.encode("utf-8")) > _MAX_PARSE_BYTES:
            raise LocalContextError("LimitExceeded")
        if "\r" in text.replace("\r\n", ""):
            raise LocalContextError("InvalidInput")
        # Parser diagnostics can contain source snippets. Do not emit them or chain exceptions.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            module = ast.parse(text, filename="<cigar-source>")
    except (SyntaxError, ValueError, RecursionError, UnicodeError):  # fmt: skip
        raise LocalContextError("InvalidInput") from None
    lines = []
    for node in module.body:
        first = node.lineno
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            first = min([first, *(decorator.lineno for decorator in node.decorator_list)])
        lines.append(first)
    starts = [start + line - 1 for line in sorted(set(lines))[1:]]
    if len(starts) >= 4096 or (starts and starts[-1] > 2**64 - 1):
        raise LocalContextError("LimitExceeded")
    return starts


def run_syntax_ingestion(*, worker_path: str | Path | None = None) -> dict[str, object]:
    """Partition, admit, link and compile known fixture code without executing that code."""
    if not __debug__:
        raise RuntimeError("Run the self-checking example without Python -O.")
    document: LocalDocument = {
        "id": "retry-module",
        "source": "project://retry.py",
        "start_line": 40,
        "text": (
            "# Explicit source; no file is opened.\nMAX_ATTEMPTS = 3\n\n"
            "def preserve_id(operation_id):\n    return operation_id\n\n"
            "@traced(\n    label='retry',\n)\n"
            "async def retry_operation(\n    operation_id,\n):\n"
            "    return preserve_id(operation_id), MAX_ATTEMPTS\n"
        ),
    }
    with LocalContextGraph("syntax-example", worker_path=worker_path) as graph:
        starts = python_boundaries(document)
        chunks = graph.chunks_at_lines(document, starts)
        assert "".join(chunk["text"] for chunk in chunks) == document["text"]
        assert len(chunks) == 3
        for chunk in chunks:
            ast.parse(chunk["text"])
        assert graph.stats()["documents"] == 0
        graph.replace_source(document["source"], chunks)
        # Explicit fixture dependencies, not inferred authority or general Python dataflow.
        root = chunks[2]["id"]
        graph.link(root, chunks[0]["id"], "requires")
        graph.link(root, chunks[1]["id"], "requires")
        result = graph.compile({"required": [root], "max_tokens": 1024})
        selected = {citation["node_id"] for block in result["snapshot"]["blocks"] for citation in block["citations"]}
        assert selected == {chunk["id"] for chunk in chunks}
        assert graph.verify(result["snapshot"]) == result
        return {
            "schema": "cigar.syntax-ingestion-example.v1",
            "status": "passed",
            "parser": "host-python-ast",
            "chunks": len(chunks),
            "exact_source_partition": True,
            "selected_sources": len(selected),
            "rendered_tokens": result["snapshot"]["stats"]["rendered_tokens"],
            "requires_hol_services": False,
        }


if __name__ == "__main__":
    print(json.dumps(run_syntax_ingestion(), indent=2))
