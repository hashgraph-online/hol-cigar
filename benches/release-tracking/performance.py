"""Paired persistent-worker measurements with complete response parity checks."""
from collections import defaultdict
import copy
import hashlib
import json
import math
import random
import statistics

from worker import Worker, canonical


def distribution(values):
    ordered = sorted(values)
    return {"n": len(values), "median": statistics.median(values),
            "p95_nearest_rank": ordered[math.ceil(.95 * len(ordered)) - 1], "min": ordered[0], "max": ordered[-1]}


def paired_interval(pairs):
    # One value per new process session; repeated requests never become bootstrap units.
    reductions = [100 * (1 - candidate / baseline) for baseline, candidate in pairs]
    rng = random.Random(110024)
    samples = sorted(statistics.median(rng.choices(reductions, k=len(reductions))) for _ in range(2000))
    interval = [samples[49], samples[1949]]
    median = statistics.median(reductions)
    return {"paired_sessions": len(pairs), "paired_median_reduction_percent": median,
            "descriptive_95_percent_interval": interval,
            "improvement_threshold_met": median >= 10 and interval[0] > 0}


def corpus(config):
    docs = []
    size = config["documents_per_query"]
    for index in range(config["documents"]):
        lines = [f"topic_{index // size} service_{index} fact_{line}: retry budget {index + line}; retain the exact event payload, source identity and negative observation.\n" for line in range(6)]
        docs.append({"id": f"node-{index:04d}", "source": "fixture/performance", "text": "".join(lines)})
    requests = [{"query": f"topic_{offset // size}", "required": [d["id"] for d in docs[offset:offset + size]],
                 "max_tokens": config["max_tokens"], "max_candidates": 32, "max_blocks": size}
                for offset in range(0, len(docs), size)]
    if config.get("query_mode") == "required_only":
        for request in requests:
            request["query"] = "unmatchedmarker"
    return docs, requests


def session(build, mode, pair, config, output):
    name = f"{mode}-{pair:02d}-{build['version']}"
    limits = {"cache_entries": 256, "cache_text_bytes": 8 * 1024 * 1024} if mode == "equal_256_entry_cache" else {}
    worker = Worker(build["binary"], build["version"], output / f"{name}.trace.jsonl.gz", domain="tracking/performance", limits=limits)
    docs, requests = corpus(config)
    signatures, timings, checks = [], defaultdict(list), []

    def keep(result):
        signatures.append(hashlib.sha256(canonical(result)).hexdigest())

    def compile_(request, phase, measured=True):
        worker.tag = phase
        result, spent = worker.ok({"op": "compile", "request": request})
        snapshot = result["snapshot"]
        selected = {c["node_id"] for b in snapshot["blocks"] for c in b["citations"]}
        assert set(request.get("required", [])) <= selected
        assert snapshot["stats"]["rendered_tokens"] <= request["max_tokens"]
        keep(result)
        if measured:
            timings[phase].append(spent)
        return result, spent

    try:
        initial, _ = worker.ok({"op": "replace_source", "source": "fixture/performance", "documents": docs})
        keep(initial)
        for request in requests:
            compile_(request, "first_rotation")
        for _ in range(config["warmup_rotations"]):
            for request in requests:
                compile_(request, "warmup", measured=False)
        before, _ = worker.ok({"op": "stats"})
        for _ in range(config["measured_rotations"]):
            for request in requests:
                compile_(request, "warm_rotation")
        after, _ = worker.ok({"op": "stats"})
        for phase in ("unchanged_refresh_and_compile", "changed_refresh_and_compile"):
            for trial in range(config["refresh_trials"] + 1):
                incoming = copy.deepcopy(docs)
                if phase.startswith("changed") and trial % 2 == 0:
                    incoming[0]["text"] += "Additional current observation: state changed.\n"
                worker.tag = phase
                update, update_ms = worker.ok({"op": "replace_source", "source": "fixture/performance", "documents": incoming})
                keep(update)
                _, compile_ms = compile_(requests[0], phase, measured=False)
                if trial:
                    timings[phase].append(update_ms + compile_ms)

        base, _ = compile_(requests[0], "contracts", measured=False)
        worker.tag = "contracts"
        invalid = copy.deepcopy(docs[:1])
        invalid[0]["source"] = "wrong-source"
        reply, _ = worker.call({"op": "replace_source", "source": "fixture/performance", "documents": invalid})
        assert reply.get("error") == "InvalidInput", reply
        keep({k: v for k, v in reply.items() if k != "id"})
        unchanged, _ = compile_(requests[0], "contracts", measured=False)
        assert base == unchanged
        checks.append("invalid_source_update_is_atomic")
        reply, _ = worker.call({"op": "compile", "request": requests[0] | {"max_tokens": 1}})
        assert reply.get("error") == "BudgetUnsatisfiable", reply
        keep({k: v for k, v in reply.items() if k != "id"})
        checks.append("budget_failure_preserves_required_evidence")
        reply, _ = worker.call({"op": "compile", "request": requests[0] | {"allowed": []}})
        assert reply.get("error") == "RequiredUnavailable", reply
        keep({k: v for k, v in reply.items() if k != "id"})
        checks.append("authorization_is_not_overridden_by_cache")
        corrupted = copy.deepcopy(base["snapshot"])
        corrupted["blocks"][0]["text"] += " fabricated"
        reply, _ = worker.call({"op": "verify", "snapshot": corrupted})
        assert reply.get("error") == "Integrity", reply
        keep({k: v for k, v in reply.items() if k != "id"})
        checks.append("cached_snapshot_tampering_rejected")
        worker.ok({"op": "upsert", "document": docs[0] | {"text": docs[0]["text"] + "New delta observation."}})
        target, _ = compile_(requests[0], "contracts", measured=False)
        delta, _ = worker.ok({"op": "delta", "base": base["snapshot"], "target": target["snapshot"]})
        keep(delta)
        applied, _ = worker.ok({"op": "apply_delta", "base": base["snapshot"], "delta": delta})
        assert applied == target
        keep(applied)
        checks.append("source_change_delta_round_trip")
        worker.ok({"op": "remove", "node_id": docs[0]["id"]})
        reply, _ = worker.call({"op": "compile", "request": requests[0]})
        assert reply.get("error") == "RequiredUnavailable", reply
        keep({k: v for k, v in reply.items() if k != "id"})
        checks.append("withdrawn_source_not_served_from_cache")
        stats, _ = worker.ok({"op": "stats"})
        maximum = 256 if limits else (1024 if build["version"] == "0.10.0-beta.1" else 2048)
        assert stats["cache"]["entries"] <= maximum and stats["cache"]["text_bytes"] <= 8 * 1024 * 1024
        checks.append("cache_remains_bounded")
    finally:
        resources = worker.close()
    record = {"mode": mode, "pair": pair, "version": build["version"], "timings_ms": dict(timings),
              "resources": resources, "complete_response_digests": signatures, "checks": checks,
              "warm_cache_delta": {key: after["cache"][key] - before["cache"][key] for key in ("hits", "misses")},
              "cache_final": stats["cache"]}
    (output / f"{name}.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def run(builds, config, output):
    output.mkdir()
    records = []
    for mode in config["modes"]:
        for pair in range(config["paired_process_sessions"]):
            order = ["baseline", "candidate"] if pair % 2 == 0 else ["candidate", "baseline"]
            pair_records = {}
            for label in order:
                record = session(builds[label], mode, pair, config, output)
                records.append(record)
                pair_records[label] = record
            assert pair_records["baseline"]["complete_response_digests"] == pair_records["candidate"]["complete_response_digests"], (mode, pair)
            print(json.dumps({"performance_mode": mode, "completed_pairs": pair + 1, "total_pairs": config["paired_process_sessions"]}), flush=True)
    summary = {"modes": {}, "complete_response_pairs_verified": sum(len(r["complete_response_digests"]) for r in records if r["version"] == builds["baseline"]["version"]),
               "checks_passed": sum(len(r["checks"]) for r in records), "sessions": len(records)}
    for mode in config["modes"]:
        selected = {label: [r for r in records if r["mode"] == mode and r["version"] == build["version"]] for label, build in builds.items()}
        comparison = {}
        for phase in selected["baseline"][0]["timings_ms"]:
            phase_records = {label: [statistics.median(r["timings_ms"][phase]) for r in rows] for label, rows in selected.items()}
            comparison[phase] = {label: {"session_medians_ms": distribution(phase_records[label]),
                                         "all_requests_ms": distribution([v for r in rows for v in r["timings_ms"][phase]])}
                                 for label, rows in selected.items()}
            comparison[phase].update(paired_interval(list(zip(phase_records["baseline"], phase_records["candidate"], strict=True))))
        rss = {label: distribution([r["resources"]["peak_rss_bytes"] for r in rows]) for label, rows in selected.items()}
        comparison["resources"] = {"peak_rss_bytes": rss, "median_rss_increase_percent": 100 * (rss["candidate"]["median"] / rss["baseline"]["median"] - 1),
                                   "warm_cache_hits_misses": {label: {key: sum(r["warm_cache_delta"][key] for r in rows) for key in ("hits", "misses")} for label, rows in selected.items()},
                                   "startup_ms": {label: distribution([r["resources"]["startup_ms"] for r in rows]) for label, rows in selected.items()}}
        comparison["resources"]["rss_watch_exceeded"] = comparison["resources"]["median_rss_increase_percent"] > 20
        if "expected_warm_misses" in config:
            comparison["capacity_coverage_checks"] = {
                label: (comparison["resources"]["warm_cache_hits_misses"][label]["misses"] > 0) == expected
                for label, expected in config["expected_warm_misses"][mode].items()
            }
            assert all(comparison["capacity_coverage_checks"].values()), comparison["capacity_coverage_checks"]
        summary["modes"][mode] = comparison
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
