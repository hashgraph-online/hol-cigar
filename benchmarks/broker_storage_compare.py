"""Compare two worker artifacts using the same offline storage workload and SDK.

This isolates a native implementation change; it is not an installed-version or
model-quality comparison. Failed/missing process cohorts remain in the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import os

from broker_storage import corpus, encoded, file_hash, paired


def measurements(row):
    result = {
        operation + "_median_ms": statistics.median(values)
        for operation, values in row["raw_ms"].items()
    }
    result.update(
        total_sampled_rss_bytes=max(x["total"] for x in row["rss_samples"]),
        worker_cpu_ms=row["cpu"]["worker_ms"],
        host_cpu_ms=row["cpu"]["host_ms"],
        database_bytes=max(row["disk_samples_bytes"]),
    )
    if row["mode"] == "sqlite":
        result["resume_ms"] = row["resume_ms"]
    return result


def summarize_comparison(rows, counts, cohorts):
    result = {}
    for count in counts:
        group = [row for row in rows if row["documents"] == count]
        indexed = {(row["cohort"], row["mode"], row["variant"]): row for row in group}
        expected = {
            (cohort, mode, variant)
            for cohort in range(cohorts)
            for mode in ("memory", "sqlite")
            for variant in ("reference", "candidate")
        }
        if (
            set(indexed) != expected
            or len(group) != len(expected)
            or any(row["status"] != "ok" for row in group)
        ):
            result[str(count)] = {"status": "incomplete", "paired": None}
            continue
        for cohort in range(cohorts):
            if len({r["rendered_sha256"] for r in group if r["cohort"] == cohort}) != 1:
                raise ValueError("workers returned different context")
        modes = {}
        for mode in ("memory", "sqlite"):
            observations = {
                (cohort, variant): measurements(indexed[cohort, mode, variant])
                for cohort in range(cohorts)
                for variant in ("reference", "candidate")
            }
            metrics = {}
            for name in observations[0, "reference"]:
                pairs = [
                    (
                        observations[cohort, "reference"][name],
                        observations[cohort, "candidate"][name],
                    )
                    for cohort in range(cohorts)
                ]
                metrics[name] = {
                    "reference_median": statistics.median(a for a, _ in pairs),
                    "candidate_median": statistics.median(b for _, b in pairs),
                    **paired(pairs),
                }
            modes[mode] = metrics
        result[str(count)] = {"status": "ok", "paired": modes}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--reference-worker", required=True, type=Path)
    parser.add_argument("--reference-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--documents", nargs="+", type=int, default=[100, 1000, 5000])
    parser.add_argument("--cohorts", type=int, default=8)
    args = parser.parse_args()
    if (
        not all(path.is_absolute() for path in (args.worker, args.reference_worker))
        or not 1 <= args.cohorts <= 32
        or len(set(args.documents)) != len(args.documents)
        or any(not 1 <= count <= 10000 for count in args.documents)
        or len(args.reference_commit) != 40
        or any(c not in "0123456789abcdef" for c in args.reference_commit)
    ):
        parser.error(
            "use absolute workers, a full reference commit and bounded cohorts/corpora"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    inputs = {
        name: (root / "benchmarks" / name).read_bytes()
        for name in (
            "broker_storage_compare.py",
            "broker_storage.py",
            "shared_views.py",
        )
    }
    patch = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    workers = {"reference": args.reference_worker, "candidate": args.worker}
    identities = {
        variant: {"sha256": file_hash(path), "bytes": path.stat().st_size}
        for variant, path in workers.items()
    }
    plan = {
        "schema": "cigar.broker-storage-comparison-plan.v1",
        "candidate_source_commit": commit,
        "candidate_tracked_patch_sha256": hashlib.sha256(patch).hexdigest(),
        "reference_source_commit": args.reference_commit,
        "workers": identities,
        "harnesses": {
            name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()
        },
        "host": platform.platform(),
        "python": sys.version,
        "cohorts": args.cohorts,
        "documents": args.documents,
        "payload_bytes": 1024,
        "rounds": 12,
        "warmup_rounds": 2,
        "order": "reference memory/sqlite then candidate memory/sqlite; reversed on odd cohorts",
        "model_mode": "none",
        "network_policy": "loopback only by implementation; no OS-denied claim",
        "acceptance": "diagnostic paired worker comparison, not release qualification",
        "scope": "Identical current source SDK and workload for both workers. Explicit worker excludes "
        "bundled hashing. RSS sampled every 20ms, not PSS or exact peak. CPU excludes recovery; "
        "file sizes exclude transient journal peaks. Intervals resample whole process pairs.",
    }
    (args.output / "plan.json").write_bytes(encoded(plan))
    (args.output / "candidate.patch").write_bytes(patch)
    for name, data in inputs.items():
        (args.output / name).write_bytes(data)
    rows = []
    for count in args.documents:
        documents = encoded(corpus(count, 1024))
        corpus_hash = hashlib.sha256(documents).hexdigest()
        (args.output / f"corpus-{count}.json").write_bytes(documents)
        for cohort in range(args.cohorts):
            order = [
                (variant, mode) for variant in workers for mode in ("memory", "sqlite")
            ]
            for variant, mode in order if cohort % 2 == 0 else reversed(order):
                command = [
                    sys.executable,
                    str(root / "benchmarks/broker_storage.py"),
                    "--worker",
                    str(workers[variant]),
                    "--mode",
                    mode,
                    "--documents",
                    str(count),
                    "--rounds",
                    "12",
                    "--payload-bytes",
                    "1024",
                ]
                try:
                    process = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        env={**os.environ, "PYTHONPATH": str(root / "sdk/python/src")},
                    )
                    error = process.stderr if process.returncode else None
                except subprocess.TimeoutExpired:
                    error = "child exceeded 300-second deadline"
                if error is not None:
                    (
                        args.output / f"failure-{count}-{cohort}-{variant}-{mode}.txt"
                    ).write_text(error)
                    row = {"status": "failed", "documents": count, "mode": mode}
                else:
                    row = json.loads(process.stdout)
                    if (
                        row["worker_sha256"] != identities[variant]["sha256"]
                        or row["corpus_sha256"] != corpus_hash
                        or row["documents"] != count
                        or row["mode"] != mode
                        or row["payload_bytes"] != 1024
                    ):
                        raise RuntimeError("child used different study inputs")
                rows.append({"cohort": cohort, "variant": variant, **row})
                with (args.output / "observations.jsonl").open("ab") as handle:
                    handle.write(encoded(rows[-1]))
            print(
                f"{count} documents: paired cohort {cohort + 1}/{args.cohorts}",
                flush=True,
            )
    if (
        any(file_hash(workers[v]) != identities[v]["sha256"] for v in workers)
        or any(
            (root / "benchmarks" / name).read_bytes() != data
            for name, data in inputs.items()
        )
        or subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root)
        != patch
    ):
        raise RuntimeError("study inputs changed")
    successful = [row for row in rows if row["status"] == "ok"]
    if len({row["sdk_source_sha256"] for row in successful}) != 1:
        raise RuntimeError("SDK source changed during comparison")
    summary = summarize_comparison(rows, args.documents, args.cohorts)
    (args.output / "result.json").write_bytes(
        encoded(
            {
                "schema": "cigar.broker-storage-comparison.v1",
                "plan": plan,
                "summary": summary,
            }
        )
    )
    print(json.dumps(summary, indent=2))
    if any(result["status"] != "ok" for result in summary.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
