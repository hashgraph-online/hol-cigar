"""Offline, paired fresh-process comparison of root APIs and scoped context sharing.

Run with --baseline-python and --candidate-python pointing to installed environments.
No model, HTTP client or credential discovery is used. The scheduled write interleaving
is deterministic; separate SDK tests exercise concurrent threads/promises.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


def package_source_identity(entries):
    """Commit to package code/data, excluding bytecode and separately bound workers."""
    rows = []
    for name, payload in entries:
        parts = name.split("/")
        if "_native" in parts or "__pycache__" in parts or name.endswith(".pyc"):
            continue
        rows.append([name, hashlib.sha256(payload).hexdigest()])
    return hashlib.sha256(
        json.dumps(sorted(rows), separators=(",", ":")).encode()
    ).hexdigest()


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
    import cigar_sdk

    import_ms = (time.perf_counter_ns() - start) / 1e6
    worker = Path(args.worker) if args.worker else bundled_worker()
    with worker.open("rb") as stream:
        worker_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    package_root = Path(cigar_sdk.__file__).parent
    sdk_hash = package_source_identity(
        (path.relative_to(package_root).as_posix(), path.read_bytes())
        for path in package_root.rglob("*")
        if path.is_file()
        and "_native" not in path.parts
        and "__pycache__" not in path.parts
    )
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
    revisions = [0] * args.agents
    sampled_rss = []
    sampled_total_rss = []
    outcomes = []
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
        if sys.platform == "darwin":
            # Darwin SDK sys/proc_info.h: six uint64_t fields (resident bytes
            # second), followed by twelve int32_t counters. Query only our children.
            class TaskInfo(ctypes.Structure):
                _fields_ = [
                    ("wide", ctypes.c_uint64 * 6),
                    ("counters", ctypes.c_int32 * 12),
                ]

            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            libproc.proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            libproc.proc_pidinfo.restype = ctypes.c_int
            resident = []
            for pid in [g._process.pid for g in graphs] + [os.getpid()]:
                info = TaskInfo()
                size = ctypes.sizeof(info)
                if libproc.proc_pidinfo(pid, 4, 0, ctypes.byref(info), size) != size:
                    raise OSError(
                        ctypes.get_errno(), "cannot read benchmark worker RSS"
                    )
                resident.append(info.wide[1])
            sampled_rss.append(sum(resident[:-1]))
            sampled_total_rss.append(sum(resident))
            return
        pids = ",".join(
            str(pid) for pid in [g._process.pid for g in graphs] + [os.getpid()]
        )
        result = subprocess.run(
            ["ps", "-o", "pid=,rss=", "-p", pids],
            check=True,
            text=True,
            capture_output=True,
        )
        resident = {
            int(pid): int(rss) * 1024
            for pid, rss in (line.split() for line in result.stdout.splitlines())
        }
        assert set(resident) == {g._process.pid for g in graphs} | {os.getpid()}
        total = sum(resident.values())
        sampled_total_rss.append(total)
        sampled_rss.append(total - resident[os.getpid()])

    try:
        begin = time.perf_counter_ns()
        for _ in range(args.agents if args.mode == "private" else 1):
            graphs.append(
                LocalContextGraph("paired-alpha-benchmark", worker_path=worker)
            )
        startup_ms = (time.perf_counter_ns() - begin) / 1e6
        begin = time.perf_counter_ns()
        for graph in graphs:
            graph.replace_source("shared", docs("shared"))
        for i in range(args.agents):
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
        for i in range(args.agents):
            compile_one(i)
        for values in timings.values():
            values.clear()
        sample_rss()
        if args.mode == "legacy":
            for turn in range(args.rounds):
                data = compile_one(turn % args.agents)
                assert check(turn % args.agents, data)["decision"] == "release"
                output_hash.update(
                    json.dumps(data[1], sort_keys=True, separators=(",", ":")).encode()
                )
                totals["released"] += 1
                outcomes.append(
                    {
                        "phase": "legacy",
                        "round": turn,
                        "agent": turn % args.agents,
                        "outcome": "released",
                    }
                )
        else:
            for turn in range(args.rounds):
                compiled = [compile_one(i) for i in range(args.agents)]
                changed = turn % args.agents
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
                        outcome = (
                            "stale_expected" if i == changed else "stale_unrelated"
                        )
                        totals[outcome] += 1
                    else:
                        assert assessed["decision"] == "release"
                        outcome = "stale_accepted" if i == changed else "released"
                        totals[outcome] += 1
                    outcomes.append(
                        {
                            "phase": "refresh",
                            "round": turn,
                            "agent": i,
                            "outcome": outcome,
                        }
                    )
                assert totals["stale_accepted"] == 0
                if turn % 10 == 0:
                    sample_rss()
        for i in range(args.agents):
            data = compile_one(i)
            assert check(i, data, [])["decision"] == "abstain"
            totals["missing_review_abstained"] += 1
            outcomes.append(
                {
                    "phase": "missing-review",
                    "round": 0,
                    "agent": i,
                    "outcome": "missing_review_abstained",
                }
            )
            # Deliberately falsify the known revision; the host's independent fixture
            # oracle supplies a contradiction verdict bound to the altered claim.
            client, context, draft, _ = data
            draft = draft | {
                "claims": [
                    {
                        "text": f"agent-{i} document 0: revision {revisions[i] + 1000}.",
                        "citations": [f"agent-{i}-0"],
                        "confidence_bps": 9999,
                    }
                ]
            }
            wrong = [
                {"claim_key": key, "verdict": "contradicted"}
                for key in client.review_keys(draft)
            ]
            assessed = check(i, (client, context, draft, wrong))
            assert (
                assessed["decision"] == "abstain"
                and assessed["confident_failures"] == 1
            )
            totals["confident_wrong_abstained"] += 1
            outcomes.append(
                {
                    "phase": "wrong-claim",
                    "round": 0,
                    "agent": i,
                    "outcome": "confident_wrong_abstained",
                }
            )
        sample_rss()
        return {
            "mode": args.mode,
            "version": importlib.metadata.version("hol-cigar"),
            "protobuf": importlib.metadata.version("protobuf"),
            "python": platform.python_version(),
            "worker_sha256": worker_hash,
            "sdk_source_sha256": sdk_hash,
            "import_ms": import_ms,
            "startup_ms": startup_ms,
            "setup_ms": setup_ms,
            "workers": len(graphs),
            "indexed_documents": sum(g.stats()["documents"] for g in graphs),
            "worker_rss_sampled_max_bytes": max(sampled_rss),
            "host_and_worker_rss_sampled_max_bytes": max(sampled_total_rss),
            "raw_timing_ms": timings,
            "raw_worker_rss_bytes": sampled_rss,
            "raw_host_and_worker_rss_bytes": sampled_total_rss,
            "raw_outcomes": outcomes,
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
    harness_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
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
                "--agents",
                str(args.agents),
            ]
            if worker:
                command.extend(["--worker", worker])
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=180
            )
            if result.returncode:
                print(result.stderr, file=sys.stderr)
                result.check_returncode()
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
            "host_and_worker_rss_sampled_max_bytes_median": statistics.median(
                r["host_and_worker_rss_sampled_max_bytes"] for r in group
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
        "harness_sha256": harness_hash,
        "host": platform.platform(),
        "cohorts": args.cohorts,
        "rounds_per_cohort": args.rounds,
        "documents_per_source": args.documents,
        "agents": args.agents,
        "agent_execution": "scoped clients in one trusted host; not independent broker processes",
        "reviewer": "scripted-fixture",
        "legacy_outputs_equal": True,
        "method": "Alternating paired fresh processes; deterministic write between compile and review. "
        "RSS is maximum sampled sum of worker resident bytes, not peak allocation or PSS. "
        "A separate host-and-worker total includes the SDK host at each sample. "
        "Call quantiles within a process are descriptive, not independent statistical samples.",
        "summary": summary,
        "samples": rows,
    }
    assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == harness_hash, (
        "benchmark source changed during study"
    )
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")


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
    parser.add_argument("--agents", type=int, choices=(1, 5, 12), default=5)
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
