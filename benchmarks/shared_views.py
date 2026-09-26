"""Offline, paired fresh-process comparison of root APIs and five-agent context sharing.

Run with --baseline-python and --candidate-python pointing to installed environments.
No model, HTTP client or credential discovery is used. The scheduled write interleaving
is deterministic; separate SDK tests exercise concurrent threads/promises.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


def quantiles(values):
    ordered = sorted(values)
    return {
        "p50": statistics.median(ordered),
        "p95": ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)],
        "max": ordered[-1],
        "samples": len(ordered),
    }


def child(args):
    start = time.perf_counter_ns()
    from cigar_sdk import LocalContextError, LocalContextGraph
    from cigar_sdk.local_runtime import bundled_worker

    import_ms = (time.perf_counter_ns() - start) / 1e6
    worker = Path(args.worker) if args.worker else bundled_worker()
    with worker.open("rb") as stream:
        worker_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    graphs = []
    views = []
    timings = {name: [] for name in ("compile", "verify", "review", "replace")}
    totals = {
        name: 0
        for name in (
            "released",
            "stale_expected",
            "stale_unrelated",
            "stale_accepted",
            "missing_review_abstained",
            "confident_wrong_abstained",
        )
    }
    revisions = [0] * 5
    sampled_rss = []
    output_hash = hashlib.sha256()

    def timed(name, fn):
        begin = time.perf_counter_ns()
        try:
            return fn()
        finally:
            timings[name].append((time.perf_counter_ns() - begin) / 1e6)

    def docs(source, revision=0):
        return [
            {
                "id": f"{source}-{i}",
                "source": source,
                "text": f"{source} document {i}: revision {revision}. "
                + "Evidence remains source-bound. " * 12,
            }
            for i in range(args.documents)
        ]

    def sample_rss():
        pids = ",".join(str(g._process.pid) for g in graphs)
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", pids], check=True, text=True, capture_output=True
        )
        rows = result.stdout.split()
        assert len(rows) == len(graphs)
        sampled_rss.append(sum(int(row) for row in rows) * 1024)

    try:
        begin = time.perf_counter_ns()
        for _ in range(5 if args.mode == "private" else 1):
            graphs.append(
                LocalContextGraph("paired-alpha-benchmark", worker_path=worker)
            )
        startup_ms = (time.perf_counter_ns() - begin) / 1e6
        begin = time.perf_counter_ns()
        for graph in graphs:
            graph.replace_source("shared", docs("shared"))
        for i in range(5):
            graph = graphs[i] if args.mode == "private" else graphs[0]
            graph.replace_source(f"agent-{i}", docs(f"agent-{i}"))
            graph.link(f"agent-{i}-0", "shared-0", "requires")
            if args.mode == "views":
                views.append(
                    graph.create_view(
                        {
                            "id": f"agent-{i}",
                            "allowed_sources": ["shared", f"agent-{i}"],
                            "writable_sources": [f"agent-{i}"],
                            "policy_revision": "host-1",
                        }
                    )
                )
        setup_ms = (time.perf_counter_ns() - begin) / 1e6

        def request(i):
            value = {
                "required": [f"agent-{i}-0"],
                "query": "revision",
                "max_tokens": 2048,
                "reserve_tokens": 128,
                "policy_revision": "host-1",
            }
            if args.mode != "views":
                value["allowed"] = [
                    d["id"] for source in ("shared", f"agent-{i}") for d in docs(source)
                ]
            return value

        def compile_one(i):
            graph = graphs[i] if args.mode == "private" else graphs[0]
            client = views[i] if args.mode == "views" else graph
            result = timed("compile", lambda: client.compile(request(i)))
            context = result["context"] if args.mode == "views" else result
            snapshot = context["snapshot"]
            allowed = {"shared", f"agent-{i}"}
            for block in snapshot["blocks"]:
                assert all(c["source"] in allowed for c in block["citations"])
            assert snapshot["stats"]["rendered_tokens"] <= 1920
            assert (
                f"agent-{i} document 0: revision {revisions[i]}." in result["rendered"]
            )
            verified = timed("verify", lambda: graph.verify(snapshot))
            assert verified["rendered"] == result["rendered"]
            draft = {
                "snapshot_id": snapshot["id"],
                "claims": [
                    {
                        "text": f"agent-{i} document 0: revision {revisions[i]}.",
                        "citations": [f"agent-{i}-0"],
                        "confidence_bps": 9999,
                    }
                ],
            }
            reviews = [
                {"claim_key": key, "verdict": "supported"}
                for key in client.review_keys(draft)
            ]
            return client, context, draft, reviews

        def check(i, data, reviews=None):
            client, context, draft, original = data
            result = timed(
                "review",
                lambda: client.check_answer(
                    context if args.mode == "views" else request(i),
                    draft,
                    original if reviews is None else reviews,
                ),
            )
            return result["assessment"] if args.mode == "views" else result

        # Warm the process; these calls are excluded from measured per-call cohorts.
        for i in range(5):
            compile_one(i)
        for values in timings.values():
            values.clear()
        sample_rss()
        if args.mode == "legacy":
            for turn in range(args.rounds):
                data = compile_one(turn % 5)
                assert check(turn % 5, data)["decision"] == "release"
                output_hash.update(
                    json.dumps(data[1], sort_keys=True, separators=(",", ":")).encode()
                )
                totals["released"] += 1
        else:
            for turn in range(args.rounds):
                compiled = [compile_one(i) for i in range(5)]
                changed = turn % 5
                revisions[changed] += 1
                source = f"agent-{changed}"
                client = (
                    views[changed]
                    if args.mode == "views"
                    else graphs[changed if args.mode == "private" else 0]
                )
                timed(
                    "replace",
                    lambda: client.replace_source(
                        source, docs(source, revisions[changed])
                    ),
                )
                for i, data in enumerate(compiled):
                    try:
                        assessed = check(i, data)
                    except LocalContextError as error:
                        assert error.code == "BaseMismatch", error.code
                        totals[
                            "stale_expected" if i == changed else "stale_unrelated"
                        ] += 1
                    else:
                        assert assessed["decision"] == "release"
                        totals["stale_accepted" if i == changed else "released"] += 1
                assert totals["stale_accepted"] == 0
                if turn % 10 == 0:
                    sample_rss()
        for i in range(5):
            data = compile_one(i)
            assert check(i, data, [])["decision"] == "abstain"
            totals["missing_review_abstained"] += 1
            # An independent fixture oracle deliberately rejects this claim at high confidence.
            wrong = [
                {"claim_key": row["claim_key"], "verdict": "contradicted"}
                for row in data[3]
            ]
            assessed = check(i, data, wrong)
            assert (
                assessed["decision"] == "abstain"
                and assessed["confident_failures"] == 1
            )
            totals["confident_wrong_abstained"] += 1
        sample_rss()
        return {
            "mode": args.mode,
            "version": importlib.metadata.version("hol-cigar"),
            "protobuf": importlib.metadata.version("protobuf"),
            "python": platform.python_version(),
            "worker_sha256": worker_hash,
            "import_ms": import_ms,
            "startup_ms": startup_ms,
            "setup_ms": setup_ms,
            "workers": len(graphs),
            "indexed_documents": sum(g.stats()["documents"] for g in graphs),
            "worker_rss_sampled_max_bytes": max(sampled_rss),
            "timing_ms": {name: quantiles(v) for name, v in timings.items() if v},
            "counts": totals,
            "legacy_output_sha256": output_hash.hexdigest()
            if args.mode == "legacy"
            else None,
            "scope_budget_citation_failures": 0,
        }
    finally:
        for graph in graphs:
            graph.close()
            assert graph.cleanup_complete


def compare(args):
    variants = [
        ("012-legacy", args.baseline_python, args.baseline_worker, "legacy"),
        ("013-legacy", args.candidate_python, args.candidate_worker, "legacy"),
        ("012-shared", args.baseline_python, args.baseline_worker, "shared"),
        ("012-private", args.baseline_python, args.baseline_worker, "private"),
        ("013-views", args.candidate_python, args.candidate_worker, "views"),
    ]
    rows = []
    for cohort in range(args.cohorts):
        order = variants if cohort % 2 == 0 else list(reversed(variants))
        for label, python, worker, mode in order:
            command = [
                python,
                str(Path(__file__).resolve()),
                "--mode",
                mode,
                "--rounds",
                str(args.rounds),
                "--documents",
                str(args.documents),
            ]
            if worker:
                command.extend(["--worker", worker])
            result = subprocess.run(
                command, check=True, capture_output=True, text=True, timeout=180
            )
            rows.append(
                {"cohort": cohort, "variant": label, **json.loads(result.stdout)}
            )
        print(
            f"paired cohort {cohort + 1}/{args.cohorts} complete",
            file=sys.stderr,
            flush=True,
        )
    hashes = {r["legacy_output_sha256"] for r in rows if r["mode"] == "legacy"}
    assert len(hashes) == 1, "existing root outputs changed"
    assert (
        len({r["protobuf"] for r in rows}) == len({r["python"] for r in rows}) == 1
    ), "runtime mismatch"
    summary = {}
    for label, *_ in variants:
        group = [r for r in rows if r["variant"] == label]
        summary[label] = {
            "startup_ms_median": statistics.median(r["startup_ms"] for r in group),
            "worker_rss_sampled_max_bytes_median": statistics.median(
                r["worker_rss_sampled_max_bytes"] for r in group
            ),
            "compile_p50_ms_median": statistics.median(
                r["timing_ms"]["compile"]["p50"] for r in group
            ),
            "compile_p95_ms_median": statistics.median(
                r["timing_ms"]["compile"]["p95"] for r in group
            ),
            "review_p50_ms_median": statistics.median(
                r["timing_ms"]["review"]["p50"] for r in group
            ),
            "workers": group[0]["workers"],
            "indexed_documents": group[0]["indexed_documents"],
            "counts": {
                key: sum(r["counts"][key] for r in group) for key in group[0]["counts"]
            },
        }
    report = {
        "schema": "cigar.shared-views-comparison.v1",
        "host": platform.platform(),
        "cohorts": args.cohorts,
        "rounds_per_cohort": args.rounds,
        "documents_per_source": args.documents,
        "agents": 5,
        "reviewer": "scripted-fixture",
        "legacy_outputs_equal": True,
        "method": "Alternating paired fresh processes; deterministic write between compile and review. "
        "RSS is maximum sampled sum of worker resident bytes, not peak allocation or PSS. "
        "Call quantiles within a process are descriptive, not independent statistical samples.",
        "summary": summary,
        "samples": rows,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("legacy", "shared", "private", "views"))
    parser.add_argument("--worker")
    parser.add_argument("--baseline-python")
    parser.add_argument("--candidate-python")
    parser.add_argument("--baseline-worker")
    parser.add_argument("--candidate-worker")
    parser.add_argument("--cohorts", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=50)
    parser.add_argument("--documents", type=int, default=64)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if (
        not __debug__
        or min(arguments.cohorts, arguments.rounds, arguments.documents) < 1
    ):
        parser.error("Use normal Python execution and positive workload sizes.")
    if arguments.mode:
        print(json.dumps(child(arguments)))
    else:
        if (
            not arguments.baseline_python
            or not arguments.candidate_python
            or not arguments.output
        ):
            parser.error("Both installed Python executables and --output are required.")
        compare(arguments)
