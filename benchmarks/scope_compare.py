"""Interleave two explicit workers through the exact scoped-compilation diagnostic.

Requires byte-for-byte complete result equivalence, not only equivalent rendering.
This is a source optimization experiment, not a release qualification receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys

from broker_storage import corpus, encoded, file_hash, paired, quantiles
from scope_profile import MODES, ROOT


def compare(rows, counts, cohorts):
    report = {}
    for count in counts:
        report[str(count)] = {}
        for mode in MODES:
            group = [
                row for row in rows if row["documents"] == count and row["mode"] == mode
            ]
            expected = {
                (worker, cohort)
                for worker in ("baseline", "candidate")
                for cohort in range(cohorts)
            }
            if (
                len(group) != len(expected)
                or {(row["worker"], row["cohort"]) for row in group} != expected
            ):
                raise ValueError("missing or duplicated worker comparison process")
            if any(row["status"] != "ok" for row in group):
                report[str(count)][mode] = {"status": "incomplete"}
                continue
            if any(
                len({row[key] for row in group}) != 1
                for key in (
                    "sdk_source_sha256",
                    "corpus_sha256",
                    "result_sha256",
                    "rendered_sha256",
                )
            ):
                raise ValueError("candidate changed exact result or experiment inputs")
            summaries = {}
            for worker in ("baseline", "candidate"):
                values = [row for row in group if row["worker"] == worker]
                summaries[worker] = {
                    "process_median_ms": quantiles(
                        [statistics.median(row["raw_ms"]) for row in values]
                    ),
                    "process_peak_rss_bytes": quantiles(
                        [
                            max(sample["total"] for sample in row["rss_samples"])
                            for row in values
                        ]
                    ),
                    "descriptive_call_ms": quantiles(
                        [value for row in values for value in row["raw_ms"]]
                    ),
                }
            times, memory = [], []
            for cohort in range(cohorts):
                pair = {row["worker"]: row for row in group if row["cohort"] == cohort}
                times.append(
                    tuple(
                        statistics.median(pair[name]["raw_ms"])
                        for name in ("baseline", "candidate")
                    )
                )
                memory.append(
                    tuple(
                        max(sample["total"] for sample in pair[name]["rss_samples"])
                        for name in ("baseline", "candidate")
                    )
                )
            report[str(count)][mode] = {
                "status": "ok",
                "workers": summaries,
                "latency_paired": paired(times),
                "rss_paired": paired(memory),
                "exact_result_sha256": group[0]["result_sha256"],
            }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-worker", type=Path, required=True)
    parser.add_argument("--candidate-worker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--documents", type=int, nargs="+", default=[100, 1000, 5000])
    parser.add_argument("--cohorts", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=100)
    args = parser.parse_args()
    if (
        sys.platform not in ("darwin", "linux")
        or not all(
            path.is_absolute() and path.is_file()
            for path in (args.baseline_worker, args.candidate_worker)
        )
        or not 1 <= args.cohorts <= 32
        or not 1 <= args.rounds <= 1000
        or len(args.documents) != len(set(args.documents))
        or any(not 1 <= count <= 10000 for count in args.documents)
    ):
        parser.error("use explicit workers and a bounded Unix workload")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {
        name: (ROOT / "benchmarks" / name).read_bytes()
        for name in (
            "scope_compare.py",
            "scope_profile.py",
            "broker_storage.py",
            "shared_views.py",
        )
    }
    workers = {}
    for name, source in (
        ("baseline", args.baseline_worker),
        ("candidate", args.candidate_worker),
    ):
        digest = file_hash(source)
        target = args.output / f"{name}-worker"
        with source.open("rb") as reader, target.open("xb") as writer:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
        target.chmod(0o700)
        if file_hash(target) != digest:
            raise RuntimeError("worker changed while retaining exact bytes")
        workers[name] = {
            "file": target.name,
            "sha256": digest,
            "bytes": target.stat().st_size,
        }
    patch = subprocess.check_output(
        ["git", "diff", "HEAD", "--", "crates/cigar-context"], cwd=ROOT
    )
    (args.output / "candidate-native.diff").write_bytes(patch)
    corpora = {}
    for count in args.documents:
        payload = encoded(
            corpus(count, 256)
            + [
                {
                    "id": "hot",
                    "source": "hot",
                    "text": "Retry policy: stop after three attempts.",
                }
            ]
        )
        filename = f"corpus-{count}.json"
        (args.output / filename).write_bytes(payload)
        corpora[count] = {
            "file": filename,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    plan = {
        "schema": "cigar.scope-comparison-plan.v1",
        "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "candidate_native_patch_sha256": hashlib.sha256(patch).hexdigest(),
        "workers": workers,
        "documents": args.documents,
        "corpora": corpora,
        "rounds": args.rounds,
        "cohorts": args.cohorts,
        "host": platform.platform(),
        "python": sys.version,
        "harness": {
            name: hashlib.sha256(data).hexdigest() for name, data in sources.items()
        },
        "order": "rotate modes; alternate baseline/candidate within each paired fresh-process cohort",
        "measurement": "same scope_profile child, five warmups, measured call/RSS samples; calls include full-result canonical JSON hashing; no sampling profiler",
        "limits": "single-client source diagnostic, explicit workers; no model call or release/installed/broker-load claim; preserve worker build receipts separately",
    }
    (args.output / "plan.json").write_bytes(encoded(plan))
    for name, payload in sources.items():
        (args.output / name).write_bytes(payload)
    rows = []
    for count in args.documents:
        for cohort in range(args.cohorts):
            rotation = cohort % len(MODES)
            for mode in MODES[rotation:] + MODES[:rotation]:
                for name in (
                    ("baseline", "candidate")
                    if cohort % 2 == 0
                    else ("candidate", "baseline")
                ):
                    worker = args.output / workers[name]["file"]
                    command = [
                        sys.executable,
                        str(ROOT / "benchmarks/scope_profile.py"),
                        "--worker",
                        str(worker),
                        "--output",
                        str(args.output),
                        "--mode",
                        mode,
                        "--documents",
                        str(count),
                        "--rounds",
                        str(args.rounds),
                    ]
                    row = {
                        "status": "failed",
                        "documents": count,
                        "mode": mode,
                        "worker": name,
                        "cohort": cohort,
                    }
                    try:
                        process = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            timeout=180,
                            env={
                                **os.environ,
                                "PYTHONPATH": str(ROOT / "sdk/python/src"),
                            },
                        )
                        if process.returncode:
                            raise RuntimeError(process.stderr)
                        result = json.loads(process.stdout)
                        if (
                            result["worker_sha256"] != workers[name]["sha256"]
                            or result["corpus_sha256"] != corpora[count]["sha256"]
                            or result["mode"] != mode
                            or result["documents"] != count
                        ):
                            raise RuntimeError("child measured unexpected inputs")
                        row = {**result, "worker": name, "cohort": cohort}
                    except (
                        RuntimeError,
                        ValueError,
                        subprocess.TimeoutExpired,
                    ) as error:
                        (
                            args.output / f"failure-{count}-{cohort}-{mode}-{name}.txt"
                        ).write_text(str(error))
                    rows.append(row)
                    with (args.output / "observations.jsonl").open("ab") as stream:
                        stream.write(encoded(row))
            print(
                f"{count} documents: paired cohort {cohort + 1}/{args.cohorts}",
                flush=True,
            )
    if any(
        (ROOT / "benchmarks" / name).read_bytes() != payload
        for name, payload in sources.items()
    ) or any(
        file_hash(args.output / worker["file"]) != worker["sha256"]
        for worker in workers.values()
    ):
        raise RuntimeError("benchmark or retained workers changed")
    report = {
        "schema": "cigar.scope-comparison.v1",
        "plan": plan,
        "comparison": compare(rows, args.documents, args.cohorts),
    }
    (args.output / "result.json").write_bytes(encoded(report))
    print(json.dumps(report["comparison"], indent=2))
    if any(row["status"] != "ok" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
