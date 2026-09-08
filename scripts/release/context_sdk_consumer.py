"""Installed-wheel/sdist cross-language oracle consumer. No source-tree SDK imports."""

import json
import sys
from pathlib import Path

import cigar_sdk
from cigar_sdk import LocalContextError, LocalContextGraph

cases = json.loads(Path(sys.argv[1]).read_bytes())
worker = sys.argv[2] if len(sys.argv) > 2 else None
results = []
for case in cases:
    try:
        with LocalContextGraph(case["domain"], worker_path=worker) as graph:
            for document in case["documents"]:
                graph.upsert(document)
            for from_id, to_id, kind in case["edges"]:
                graph.link(from_id, to_id, kind)
            result = graph.compile(case["request"])
            assert graph.verify(result["snapshot"]) == result
            results.append(result)
    except LocalContextError as error:
        results.append({"error": error.code})
print(
    json.dumps(
        {
            "exports": cigar_sdk.__all__,
            "module": cigar_sdk.__file__,
            "results": results,
        },
        ensure_ascii=False,
    )
)
