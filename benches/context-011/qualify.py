#!/usr/bin/env python3
"""Reproduce exact-output, rotating-cache and incremental-update comparisons; never publish."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metrics(samples):
    return {"samples": len(samples), "median_ns": statistics.median(samples),
            "p95_ns": sorted(samples)[max(0, int(len(samples) * .95) - 1)]}


def dense_cases():
    rng = random.Random(0xC101)
    for seed in range(100):
        documents = [{"id": f"n{i:04}", "source": f"source/{i % 19}",
                      "text": f"shared {rng.choice(['alpha', 'beta', 'gamma'])} boundary item_{i % 13}\n"
                      + (f"fn item_{i % 13}() {{}}\n" if i % 7 == 0 else "contract evidence\n")
                      + "padding é😀 " * rng.randrange(0, 8)} for i in range(rng.randrange(520, 1000))]
        ids = [d["id"] for d in documents]
        requests = []
        for query in ["shared boundary", "alpha beta gamma", f"item_{seed % 13}", "missing"]:
            maximum = rng.choice([16, 32, 128, 256])
            request = {"query": query, "max_tokens": rng.choice([1, 128, 512, 2048]),
                       "max_candidates": maximum, "max_blocks": min(16, maximum),
                       "graph_depth": rng.choice([0, 1, 2, 4]), "evidence_per_term": rng.choice([1, 2, 3]),
                       "excerpt_mode": rng.choice(["full", "query_windows"])}
            if seed % 3 == 0:
                request["allowed"] = rng.sample(ids, len(ids) // 2) + ["absent"]
            if seed % 4 == 0:
                request["required"] = rng.sample(ids, 1)
            if seed % 5 == 0:
                request["semantic_candidates"] = rng.sample(ids, 5) + ["absent", ids[0], ids[0]]
            requests.append(request)
        edges = [[a, b, rng.choice(["requires", "contradicts", "supports", "related"])]
                 for a, b in (rng.sample(ids, 2) for _ in range(80))]
        incoming = [dict(d) for d in documents if d["source"] == "source/0"]
        incoming[0]["text"] += "\nchanged alpha\n"
        incoming.pop()
        incoming.append({"id": "new-slot", "source": "source/0", "text": "shared boundary NEW"})
        yield {"name": f"dense-{seed:03}", "documents": documents, "edges": edges,
               "withdrawals": rng.sample(ids[1:], 10),
               "upserts": [{"id": "reused", "source": "replacement", "text": "shared beta boundary"}],
               "source_updates": [["source/0", incoming], ["source/0", incoming],
                                  ["source/0", [{"id": "invalid", "source": "wrong", "text": "bad"}]]],
               "requests": requests}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    env = os.environ | {"PATH": str(args.cargo.parent) + os.pathsep + os.environ.get("PATH", "")}
    registry = []
    executables = {}
    for label, package in [("baseline", args.baseline / "crates/cigar-context"), ("candidate", ROOT / "crates/cigar-context")]:
        directory = args.output / label
        directory.mkdir()
        manifest = f'''[package]
name = "cigar-011-{label}"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
candidate = []
[dependencies]
cigar-context = {{ path = {json.dumps(str(package))}, features = ["bpe"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
[[bin]]
name = "probe-{label}"
path = {json.dumps(str(ROOT / 'benches/context-011/probe.rs'))}
[profile.release]
codegen-units = 1
lto = "thin"
'''
        (directory / "Cargo.toml").write_text(manifest)
        (directory / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        command = [str(args.cargo), "build", "--release", "--offline"]
        if label == "candidate":
            command += ["--features", "candidate"]
        print("build " + label, flush=True)
        result = subprocess.run(command, cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (directory / "build.log").write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError(result.stdout.decode())
        registry.append({(p["name"], p["version"]): p.get("checksum") for p in
                         tomllib.loads((directory / "Cargo.lock").read_text())["package"] if p.get("source")})
        executables[label] = directory / "target/release" / f"probe-{label}"
    assert registry[0] == registry[1], "adapter dependency drift"
    with gzip.open(ROOT / "reports/evidence/context-010-pass2/comparison-inputs.jsonl.gz", "rb") as stream:
        cases = [json.loads(line) for line in stream]
    cases.extend(dense_cases())
    data = "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases).encode()
    (args.output / "inputs.jsonl.gz").write_bytes(gzip.compress(data, mtime=0))
    rows, rss = {}, {}
    treatments = [(label, mode) for mode in ["warm", "cold", "uncached", "rotating", "updates"]
                  for label in ["baseline", "candidate"]]
    for round_index in range(2):
        for label, mode in treatments if round_index == 0 else reversed(treatments):
            key = f"{label}-{mode}-{round_index}"
            print("run " + key, flush=True)
            result = subprocess.run([sys.executable, str(ROOT / "benches/context-011/measure.py"), str(executables[label]), mode],
                                    input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (args.output / f"{key}.stderr.log").write_bytes(result.stderr)
            (args.output / f"{key}.jsonl.gz").write_bytes(gzip.compress(result.stdout, mtime=0))
            if result.returncode:
                raise RuntimeError(result.stderr.decode())
            match = re.search(r"(\d+)\s+maximum resident set size", result.stderr.decode())
            if match:
                rss[key] = int(match.group(1))
            rows[key] = [json.loads(line) for line in result.stdout.splitlines()]
    reference = rows["baseline-warm-0"]
    comparisons = 0
    samples = {}
    for key, values in rows.items():
        label, mode, _ = key.split("-")
        if mode in ["warm", "cold", "uncached"]:
            for expected, actual in zip(reference, values, strict=True):
                assert all(expected[field] == actual[field] for field in ["case", "request", "output", "updates"]), (key, actual["case"], actual["request"])
                if label == "candidate": comparisons += 1
                if actual["case"].startswith(("dense", "authored", "generated")): continue
                group = actual["case"] + ("/" + ("full" if actual["request"] % 2 == 0 else "windows") if actual["case"] == "real-source"
                                           else "/" + ("selective" if actual["request"] == 0 else "common"))
                samples.setdefault(f"{label}/{mode}/{group}", []).extend(actual["latency_ns"])
        elif mode == "rotating":
            for actual in values:
                expected = next(row for row in reference if row["case"] == "real-source" and row["request"] == actual["request"])
                assert expected["output"]["ok"]["id"] == actual["snapshot_id"]
                samples.setdefault(f"{label}/rotating/" + ("full" if actual["request"] % 2 == 0 else "windows"), []).append(actual["latency_ns"])
        else:
            for expected, actual in zip(rows["baseline-updates-0"], values, strict=True):
                assert all(expected[f] == actual[f] for f in ["kind", "cycle", "update", "snapshot_id"])
                if actual["cycle"] not in [0, 20]:
                    samples.setdefault(f"{label}/updates/{actual['kind']}", []).append(actual["latency_ns"])
    result = subprocess.run([str(executables["candidate"]), "prompt"], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    (args.output / "prompts.jsonl.gz").write_bytes(gzip.compress(result.stdout, mtime=0))
    prompt_rows = [json.loads(line) for line in result.stdout.splitlines()]
    summary = {"schema": "cigar.context-011-qualification.v1", "distinct_requests": len(reference),
               "exact_candidate_comparisons": comparisons, "successes": sum("ok" in row["output"] for row in reference),
               "expected_errors": sum("error" in row["output"] for row in reference),
               "metrics": {key: metrics(values) for key, values in samples.items()}, "peak_process_rss_bytes": rss,
               "build_ns": {key: {row["case"]: row["build_ns"] for row in values if row.get("case", "").startswith(("real-source", "scale-"))}
                            for key, values in rows.items() if "-warm-" in key},
               "prompt_tokens": {"full": sum(row["full_tokens"] for row in prompt_rows), "compact": sum(row["prompt_tokens"] for row in prompt_rows), "requests": len(prompt_rows)},
               "binaries": {label: digest(path) for label, path in executables.items()},
               "inputs_sha256": hashlib.sha256(data).hexdigest(),
               "sources": {str(path.relative_to(ROOT)): digest(path) for path in sorted((ROOT / "crates/cigar-context/src").glob("*.rs"))},
               "limitations": "Same-host, counterbalanced offline diagnostics. Exact retrieval output comparisons, not held-out answer-quality tests; RSS is whole-process peak."}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
