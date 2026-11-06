#!/usr/bin/env python3
"""Profile real cold SDK/worker calls; retain original timings and snapshots."""

import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 100:
        parser.error("rounds must be between 1 and 100")
    started = time.perf_counter_ns()
    sys.path.insert(0, str(args.sdk_root.resolve()))
    from cigar_sdk.context import LocalContextGraph
    import_ms = (time.perf_counter_ns() - started) / 1e6
    documents = [
        {"id":"action", "source":"action", "text":"Root action requires its dependency and counterevidence."},
        {"id":"dependency", "source":"dependency", "text":"Dependency: retain the operation identity."},
        {"id":"counter", "source":"counter", "text":"Counterevidence: this operation may be denied."},
        {"id":"changing", "source":"changing", "text":"Revision one: retry three times."},
        {"id":"safe", "source":"safe", "text":"Safe policy: approved for alpha."},
        {"id":"secret", "source":"secret", "text":"Secret policy: alpha private."},
    ]
    rows = []
    for order in range(args.rounds):
        begin = time.perf_counter_ns()
        graph = LocalContextGraph("cigar-performance", worker_path=args.worker.resolve())
        initialized = time.perf_counter_ns()
        try:
            capabilities = graph.capabilities()
            for document in documents:
                graph.upsert(document)
            graph.link("action", "dependency", "requires")
            graph.link("action", "counter", "contradicts")
            ingested = time.perf_counter_ns()
            result = graph.compile({"query":"policy owner retry action", "allowed":[d["id"] for d in documents],
                                    "required":["action"], "max_tokens":2048, "max_blocks":4096, "max_candidates":4096})
            queried = time.perf_counter_ns()
            warm = graph.compile({"query":"policy owner retry action", "allowed":[d["id"] for d in documents],
                                  "required":["action"], "max_tokens":2048, "max_blocks":4096, "max_candidates":4096})
            repeated = time.perf_counter_ns()
            if warm != result:
                raise RuntimeError("Repeated unchanged compilation returned different data")
        finally:
            graph.close()
        closed = time.perf_counter_ns()
        rows.append({"order":order, "initialize_ms":(initialized-begin)/1e6,
                     "ingest_ms":(ingested-initialized)/1e6, "compile_ms":(queried-ingested)/1e6,
                     "warm_compile_ms":(repeated-queried)/1e6, "close_ms":(closed-repeated)/1e6,
                     "cold_query_ms":(queried-begin)/1e6, "snapshot":result,
                     "cleanup_complete":graph.cleanup_complete, "capabilities":capabilities})
    fields = [key for key in rows[0] if key.endswith("_ms")]
    output = {"schema":"cigar.query-profile.v1", "worker_sha256":hashlib.sha256(args.worker.read_bytes()).hexdigest(),
              "sdk_import_ms":import_ms, "rounds":args.rounds, "rows":rows,
              "median_ms":{key:statistics.median(row[key] for row in rows) for key in fields},
              "scope":"Cold local worker plus ingest and compile; import and repeated-query phases are separate"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(output, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"version":rows[0]["capabilities"]["core_version"], "import_ms":import_ms,
                      "median_ms":output["median_ms"], "rounds":args.rounds, "output":str(args.output)},indent=2))


if __name__ == "__main__":
    main()
