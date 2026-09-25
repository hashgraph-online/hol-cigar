"""Paired offline comparison of actual installed 0.11/0.12 Python distributions.

Run under an OS network-deny policy. This never patches either installation.
The authored answer-review labels are fixture oracles, not model judgments.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def measure(case, memory=False):
    if case == "graph_open":
        from cigar_sdk import LocalContextGraph
    if case == "hash":
        from cigar_sdk.local_runtime import bundled_worker
    if memory:
        import tracemalloc
        tracemalloc.start()
    start = time.perf_counter_ns()
    if case == "import":
        import cigar_sdk  # noqa: F401 -- the import itself is the measured operation
    elif case == "local_api":
        from cigar_sdk import LocalContextGraph
    elif case == "remote_api":
        from cigar_sdk import CigarClient  # noqa: F401 -- resolve the public lazy export
    elif case in {"graph_open", "first_graph"}:
        from cigar_sdk import LocalContextGraph
        graph = LocalContextGraph("installed-comparison")
    elif case == "hash":
        bundled_worker()
    else:
        raise ValueError(case)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    peak = tracemalloc.get_traced_memory()[1] if memory else None
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    if case in {"graph_open", "first_graph"}:
        assert graph.stats()["documents"] == 0
        graph.close()
    return {"ms": elapsed, "python_peak_bytes": peak, "parent_peak_rss_bytes": rss}


def rpc():
    from cigar_sdk import LocalContextGraph
    documents = [{"id": f"d{i:04}", "source": f"repo/{i}.rs", "text":
                  f"Function item_{i} checks caller authorization before retries. Reject missing evidence. " * 4}
                 for i in range(768)]
    requests = [{"query": f"item_{q * 12}", "required": [f"d{i:04}" for i in range(q * 12, q * 12 + 12)],
                 "max_tokens": 4096, "reserve_tokens": 128} for q in range(64)]
    elapsed, identities, updates = [], [], []
    with LocalContextGraph("paired-rpc") as graph:
        graph.replace_source("repo", [{**item, "source": "repo"} for item in documents])
        for rotation in range(4):
            current = []
            for request in requests:
                start = time.perf_counter_ns()
                result = graph.compile(request)
                ms = (time.perf_counter_ns() - start) / 1e6
                assert graph.verify(result["snapshot"]) == result
                assert result["snapshot"]["stats"]["rendered_tokens"] <= 3968
                current.append(digest(result))
                if rotation:
                    elapsed.append(ms)
            if identities:
                assert identities == current
            identities = current
        base = graph.compile(requests[0])["snapshot"]
        for iteration in range(9):
            start = time.perf_counter_ns()
            graph.upsert({**documents[0], "source": "repo", "text": f"Changed source revision {iteration}: reject retries."})
            target = graph.compile(requests[0])
            delta = graph.delta(base, target["snapshot"])
            assert graph.apply_delta(base, delta) == target
            if iteration:
                updates.append((time.perf_counter_ns() - start) / 1e6)
            base = target["snapshot"]
    return {"compile_ms": elapsed, "update_compile_delta_ms": updates, "identities": identities,
            "parent_peak_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "worker_peak_rss": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}


def contracts(directory):
    from cigar_sdk import LocalContextError, LocalContextGraph, ValidationError, bundle_id, verify_bundle
    from importlib import metadata, resources
    import cigar_sdk
    compilation = []
    for case in json.loads((directory / "compile-cases.json").read_text()):
        try:
            with LocalContextGraph(case["domain"]) as graph:
                for document in case["documents"]:
                    graph.upsert(document)
                for source, target, kind in case["edges"]:
                    graph.link(source, target, kind)
                result = graph.compile(case["request"])
                assert graph.verify(result["snapshot"]) == result
                compilation.append(result)
        except LocalContextError as error:
            compilation.append({"error": error.code})
    answers = []
    for case in json.loads((directory / "answer-cases.json").read_text()):
        for confidence in (None, 0, 7999, 8000, 10000):
            with LocalContextGraph("answer-comparison") as graph:
                for document in case["documents"]:
                    graph.upsert(document)
                for source, target, kind in case["edges"]:
                    graph.link(source, target, kind)
                snapshot = graph.compile(case["request"])["snapshot"]
                draft = {"snapshot_id": snapshot["id"], "claims": [c | {"confidence_bps": confidence} for c in case["claims"]],
                         "abstain": case.get("abstain", False)}
                keys = graph.review_keys(draft)
                reviews = [{"claim_key": key, "verdict": verdict, "reviewed_counterevidence": case["counterevidence"]}
                           for key, verdict in zip(keys, case["verdicts"], strict=True) if verdict]
                if case.get("alter") == "text":
                    draft["claims"][0]["text"] += " This is certain."
                if case.get("alter") == "confidence":
                    draft["claims"][0]["confidence_bps"] = 5000
                if case.get("alter") == "duplicate-review":
                    reviews += copy.deepcopy(reviews)
                for mutation in case["mutations"]:
                    graph._call(mutation)
                try:
                    result = graph.check_answer(case["request"] | case.get("request_after", {}), draft, reviews, case["policy"])
                    actual = result["decision"]
                except LocalContextError as error:
                    actual = error.code
                assert actual == case["expected"], (case["name"], confidence, actual)
                answers.append({"case": case["name"], "confidence": confidence, "actual": actual})
    golden = json.loads(resources.files("cigar_sdk.fixtures").joinpath("semantic-bundle-v1.json").read_text())
    verify_bundle(golden["bundle"])
    ambiguous = []
    for mapping in ({1: "first", "1": "second"}, {"é": "first", "e\u0301": "second"}):
        record = copy.deepcopy(golden["bundle"])
        record["extensions"] = mapping
        try:
            record["bundle_id"] = bundle_id(record)
            verify_bundle(record)
            ambiguous.append("accepted")
        except ValidationError:
            ambiguous.append("rejected")
    return {"version": metadata.version("hol-cigar"), "protobuf": metadata.version("protobuf"),
            "sdk_path": cigar_sdk.__file__, "compile_results": compilation, "answer_results": answers,
            "golden_id": bundle_id(golden["bundle"]), "ambiguous_mapping_outcomes": ambiguous,
            "exports": cigar_sdk.__all__}


def stats(values):
    return {"n": len(values), "p50": statistics.median(values),
            "p95": sorted(values)[math.ceil(.95 * len(values)) - 1], "max": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rounds", type=int, default=25)
    parser.add_argument("--probe")
    parser.add_argument("--memory", action="store_true")
    args = parser.parse_args()
    if args.probe:
        value = (contracts(args.output) if args.probe == "contracts" else rpc() if args.probe == "rpc"
                 else measure(args.probe, args.memory))
        print(json.dumps(value, ensure_ascii=False))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / "scripts/release"))
    from context_sdk_cases import build_cases
    spec = importlib.util.spec_from_file_location("answer_cases", ROOT / "benches/answer-quality/qualify.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (args.output / "compile-cases.json").write_text(json.dumps(build_cases(ROOT)))
    (args.output / "answer-cases.json").write_text(json.dumps(module.cases()))
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "LANG"}}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    interpreters = {"0.11.0": args.baseline.absolute(), "0.12.0": args.candidate.absolute()}
    def run(version, case, memory=False):
        command = [str(interpreters[version]), str(Path(__file__).resolve()), "--probe", case, "--output", str(args.output)]
        if memory:
            command.append("--memory")
        result = subprocess.run(command, cwd=args.output, env=env, capture_output=True, text=True, timeout=180, check=True)
        return json.loads(result.stdout)
    contract_results = {version: run(version, "contracts") for version in interpreters}
    for version, result in contract_results.items():
        assert result["version"] == version
        (args.output / f"contracts-{version}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    left, right = contract_results.values()
    for key in ("compile_results", "answer_results", "golden_id", "exports"):
        assert left[key] == right[key], key
    assert left["ambiguous_mapping_outcomes"] == ["accepted", "accepted"]
    assert right["ambiguous_mapping_outcomes"] == ["rejected", "rejected"]
    rows = []
    for case in ("import", "local_api", "remote_api", "first_graph", "graph_open", "hash"):
        for index in range(-2, args.rounds):
            order = list(interpreters) if index % 2 else list(reversed(interpreters))
            for version in order:
                observed = run(version, case)
                if index >= 0:
                    rows.append({"case": case, "version": version, "round": index, "memory": False, **observed})
        for index in range(5):
            for version in interpreters:
                rows.append({"case": case, "version": version, "round": index, "memory": True, **run(version, case, True)})
        print(f"measured {case}", flush=True)
    rpc_rows = []
    for index in range(8):
        for version in (list(interpreters) if index % 2 else list(reversed(interpreters))):
            rpc_rows.append({"version": version, "round": index, **run(version, "rpc")})
        assert rpc_rows[-1]["identities"] == rpc_rows[-2]["identities"]
        print(f"measured RPC pair {index + 1}/8", flush=True)
    summary = {case: {version: stats([row["ms"] for row in rows if row["case"] == case and row["version"] == version and not row["memory"]])
                     for version in interpreters} for case in sorted({row["case"] for row in rows})}
    report = {"schema": "cigar.installed-comparison.v1", "platform": platform.platform(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "interpreters": {key: str(value) for key, value in interpreters.items()},
              "provider_calls": 0, "compile_cases": len(left["compile_results"]), "compile_equivalent": True,
              "answer_cases": len(left["answer_results"]), "answer_equivalent": True,
              "startup": summary, "observations": rows, "rpc_observations": rpc_rows,
              "rpc_session_medians": {version: {metric: stats([statistics.median(row[metric]) for row in rpc_rows if row["version"] == version])
                  for metric in ("compile_ms", "update_compile_delta_ms")} for version in interpreters},
              "limitations": ["Warm filesystem caches; fresh processes; timings descriptive on one host.",
                  "Answer labels are authored fixtures; no measurement of a live model hallucination rate.",
                  "RPC medians use eight independent worker sessions per version; within-session calls are dependent."]}
    (args.output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "passed", "compile_cases": report["compile_cases"], "answer_cases": report["answer_cases"]}))


if __name__ == "__main__":
    main()
