"""Offline source diagnostic: isolate view-scope cost from indexed retrieval and IPC.

Fresh graph/root, one-source view and full-scope view processes use identical
documents and select the same required evidence. No broker, model or service call.
Optional macOS/Python profiling runs AFTER measured calls and RSS sampling.
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from broker_storage import Sampler, corpus, encoded, file_hash, paired, quantiles
from shared_views import package_source_identity


MODES = ("root", "view-one", "view-all")
ROOT = Path(__file__).resolve().parents[1]


def child(args):
    import cigar_sdk
    from cigar_sdk import LocalContextGraph

    sdk = Path(cigar_sdk.__file__).parent
    source_hash = package_source_identity(
        (path.relative_to(sdk).as_posix(), path.read_bytes())
        for path in sdk.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and "_native" not in path.parts
    )
    documents = corpus(args.documents[0], 256)
    required = {
        "id": "hot",
        "source": "hot",
        "text": "Retry policy: stop after three attempts.",
    }
    request = {"query": "retry policy", "required": ["hot"], "max_tokens": 512}
    timings, outputs = [], []
    worker_hash = file_hash(args.worker)
    with LocalContextGraph(
        "scope-profile", worker_path=args.worker, timeout=120
    ) as graph:
        graph.replace_source("cold", documents)
        graph.replace_source("hot", [required])
        target = (
            graph
            if args.mode == "root"
            else graph.create_view(
                {
                    "id": "reader",
                    "policy_revision": "fixed-host-policy",
                    "allowed_sources": ["hot"]
                    if args.mode == "view-one"
                    else ["cold", "hot"],
                }
            )
        )

        def compile_one():
            result = target.compile(request)
            snapshot = (
                result["snapshot"]
                if args.mode == "root"
                else result["context"]["snapshot"]
            )
            selected = {
                citation["node_id"]
                for block in snapshot["blocks"]
                for citation in block["citations"]
            }
            if (
                selected != {"hot"}
                or snapshot["stats"]["rendered_tokens"] > 512
                or required["text"] not in result["rendered"]
            ):
                raise RuntimeError(
                    "scope profiling changed selected evidence or budget"
                )
            return hashlib.sha256(result["rendered"].encode()).hexdigest()

        for _ in range(5):
            compile_one()
        sampler = Sampler(graph._process.pid)
        sampler.thread.start()
        try:
            for _ in range(args.rounds):
                start = time.perf_counter_ns()
                output = compile_one()
                timings.append((time.perf_counter_ns() - start) / 1e6)
                outputs.append(output)
        finally:
            sampler.close()
        profiles = None
        if args.native_profile:
            # Known fixture process only. The sampling pass is excluded from all latency/RSS rows.
            prefix = args.output / f"profile-{args.mode}"
            native = prefix.with_suffix(".native.txt")
            python = prefix.with_suffix(".python.pstats")
            if native.exists() or python.exists():
                raise RuntimeError("profiling output already exists")
            sampling = subprocess.Popen(
                [
                    "/usr/bin/sample",
                    str(graph._process.pid),
                    "5",
                    "1",
                    "-file",
                    str(native),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline:
                    compile_one()
                stdout, stderr = sampling.communicate(timeout=15)
                if sampling.returncode or not native.is_file():
                    raise RuntimeError(f"native profiler failed: {stdout}{stderr}")
            finally:
                if sampling.poll() is None:
                    sampling.kill()
                    sampling.wait(timeout=5)
            profiler = cProfile.Profile()
            profiler.enable()
            for _ in range(100):
                compile_one()
            profiler.disable()
            profiler.dump_stats(str(python))
            profiles = {
                "native": {"file": native.name, "sha256": file_hash(native)},
                "python": {"file": python.name, "sha256": file_hash(python)},
                "measured_calls_exclude_profiling": True,
            }
    if not graph.cleanup_complete or len(set(outputs)) != 1:
        raise RuntimeError("cleanup or deterministic output failed")
    return {
        "status": "ok",
        "mode": args.mode,
        "documents": len(documents),
        "corpus_sha256": hashlib.sha256(encoded(documents + [required])).hexdigest(),
        "worker_sha256": worker_hash,
        "sdk_source_sha256": source_hash,
        "python": platform.python_version(),
        "raw_ms": timings,
        "rss_samples": sampler.samples,
        "rendered_sha256": outputs[0],
        "profiles": profiles,
    }


def summarize(rows, counts, cohorts):
    summaries = {}
    for count in counts:
        selected = [row for row in rows if row["documents"] == count]
        identities = {(row["mode"], row["cohort"]) for row in selected}
        expected = {(mode, cohort) for mode in MODES for cohort in range(cohorts)}
        if len(selected) != len(expected) or identities != expected:
            raise ValueError("missing or duplicate scope-profile process")
        if any(row["status"] != "ok" for row in selected):
            summaries[str(count)] = {"status": "incomplete"}
            continue
        if (
            len({row["rendered_sha256"] for row in selected}) != 1
            or len({row["corpus_sha256"] for row in selected}) != 1
        ):
            raise ValueError(
                "scope-profile treatments changed the workload or selected context"
            )
        groups = {
            mode: [row for row in selected if row["mode"] == mode] for mode in MODES
        }
        import statistics

        by_mode = {
            mode: {
                "process_median_ms": quantiles(
                    [statistics.median(row["raw_ms"]) for row in group]
                ),
                "descriptive_call_ms": quantiles(
                    [value for row in group for value in row["raw_ms"]]
                ),
                "sampled_host_worker_rss_bytes": quantiles(
                    [
                        max(sample["total"] for sample in row["rss_samples"])
                        for row in group
                    ]
                ),
            }
            for mode, group in groups.items()
        }
        comparisons = {}
        for mode in MODES[1:]:
            values = []
            for cohort in range(cohorts):
                pair = {row["mode"]: row for row in selected if row["cohort"] == cohort}
                values.append(
                    (
                        statistics.median(pair["root"]["raw_ms"]),
                        statistics.median(pair[mode]["raw_ms"]),
                    )
                )
            comparisons[mode] = paired(values)
        summaries[str(count)] = {
            "status": "ok",
            "treatments": by_mode,
            "paired_vs_root": comparisons,
        }
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--documents", type=int, nargs="+", default=[100, 1000, 5000])
    parser.add_argument("--cohorts", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=100)
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument(
        "--native-profile",
        action="store_true",
        help="macOS sample/cProfile, once per mode at the largest count",
    )
    args = parser.parse_args()
    if (
        sys.platform not in ("darwin", "linux")
        or not args.worker.is_absolute()
        or not 1 <= args.cohorts <= 32
        or not 1 <= args.rounds <= 1000
        or len(set(args.documents)) != len(args.documents)
        or any(not 1 <= count <= 10000 for count in args.documents)
        or (args.native_profile and sys.platform != "darwin")
    ):
        parser.error(
            "use an explicit absolute worker and bounded workload; native sampling requires macOS"
        )
    if args.mode:
        if len(args.documents) != 1:
            parser.error("a child measures one corpus")
        print(json.dumps(child(args), allow_nan=False))
        return
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {
        name: (ROOT / "benchmarks" / name).read_bytes()
        for name in ("scope_profile.py", "broker_storage.py", "shared_views.py")
    }
    worker_hash = file_hash(args.worker)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    )
    plan = {
        "schema": "cigar.scope-profile-plan.v1",
        "source_commit": commit,
        "source_worktree_dirty": dirty,
        "worker_sha256": worker_hash,
        "worker_bytes": args.worker.stat().st_size,
        "harness": {
            name: hashlib.sha256(data).hexdigest() for name, data in sources.items()
        },
        "host": platform.platform(),
        "python": sys.version,
        "documents": args.documents,
        "rounds": args.rounds,
        "warmups": 5,
        "cohorts": args.cohorts,
        "treatments": list(MODES),
        "order": "rotating root/view-one/view-all within fresh-process cohorts",
        "model_mode": "none",
        "network_policy": "no network path in this harness; no OS sandbox claim",
        "measurement": "Source SDK with explicit worker; retain worker build settings separately. Startup/ingestion excluded. Latency includes SDK, JSON, pipe, native compile, validation and output hashing. RSS samples simultaneous host+worker every 20ms. Sampling passes follow measured calls and are excluded.",
        "acceptance": "diagnostic only; not installed-artifact or release qualification, agent-load testing or version benefit",
    }
    (args.output / "plan.json").write_bytes(encoded(plan))
    for name, payload in sources.items():
        (args.output / name).write_bytes(payload)
    rows = []
    for count in args.documents:
        documents = corpus(count, 256) + [
            {
                "id": "hot",
                "source": "hot",
                "text": "Retry policy: stop after three attempts.",
            }
        ]
        digest = hashlib.sha256(encoded(documents)).hexdigest()
        (args.output / f"corpus-{count}.json").write_bytes(encoded(documents))
        for cohort in range(args.cohorts):
            rotation = cohort % len(MODES)
            for mode in MODES[rotation:] + MODES[:rotation]:
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    str(args.worker),
                    "--output",
                    str(args.output),
                    "--mode",
                    mode,
                    "--documents",
                    str(count),
                    "--rounds",
                    str(args.rounds),
                ]
                if args.native_profile and cohort == 0 and count == max(args.documents):
                    command.append("--native-profile")
                row = {
                    "status": "failed",
                    "mode": mode,
                    "documents": count,
                    "cohort": cohort,
                }
                try:
                    process = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=180,
                        env={**os.environ, "PYTHONPATH": str(ROOT / "sdk/python/src")},
                    )
                    if process.returncode:
                        raise RuntimeError(process.stderr)
                    result = json.loads(process.stdout)
                    if (
                        result["worker_sha256"] != worker_hash
                        or result["corpus_sha256"] != digest
                        or result["mode"] != mode
                        or result["documents"] != count
                    ):
                        raise RuntimeError("profile inputs drifted")
                    row = {**result, "cohort": cohort}
                except (subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
                    (args.output / f"failure-{count}-{cohort}-{mode}.txt").write_text(
                        str(error)
                    )
                rows.append(row)
                with (args.output / "observations.jsonl").open("ab") as stream:
                    stream.write(encoded(row))
            print(f"{count} documents: cohort {cohort + 1}/{args.cohorts}", flush=True)
    if file_hash(args.worker) != worker_hash or any(
        (ROOT / "benchmarks" / name).read_bytes() != payload
        for name, payload in sources.items()
    ):
        raise RuntimeError("worker or profiling harness changed during study")
    successful = [row for row in rows if row["status"] == "ok"]
    if len({row["sdk_source_sha256"] for row in successful}) != 1:
        raise RuntimeError("SDK source changed or no successful runs")
    report = {
        "schema": "cigar.scope-profile.v1",
        "plan": plan,
        "summary": summarize(rows, args.documents, args.cohorts),
    }
    (args.output / "result.json").write_bytes(encoded(report))
    print(json.dumps(report["summary"], indent=2))
    if len(successful) != len(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
