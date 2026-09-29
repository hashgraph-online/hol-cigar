"""Offline development probe: paired fresh-process memory and SQLite brokers.

This is a storage-cost study, not a v0.12 comparison, model-quality study or
installed-artifact qualification. Every treatment uses the same explicit worker.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import resource
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time

from shared_views import package_source_identity


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def file_hash(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def corpus(count, payload_bytes):
    result = []
    for index in range(count):
        prefix = f"Reference note {index:06d}. "
        text = (prefix + "Archival material. " * (payload_bytes // 19 + 1))[
            :payload_bytes
        ]
        result.append({"id": f"cold-{index}", "source": "cold", "text": text})
    return result


class Sampler:
    """Simultaneous resident-byte samples, not PSS or exact allocation peaks."""

    def __init__(self, worker_pid):
        self.pids = (os.getpid(), worker_pid)
        self.samples = []
        self.errors = []
        self.stop = threading.Event()
        if sys.platform == "darwin":

            class TaskInfo(ctypes.Structure):
                _fields_ = [
                    ("wide", ctypes.c_uint64 * 6),
                    ("counters", ctypes.c_int32 * 12),
                ]

            self.info_type = TaskInfo
            self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.lib.proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            self.lib.proc_pidinfo.restype = ctypes.c_int
        self.thread = threading.Thread(target=self.run, daemon=True)

    def resident(self, pid):
        if sys.platform == "darwin":
            info = self.info_type()
            size = ctypes.sizeof(info)
            if self.lib.proc_pidinfo(pid, 4, 0, ctypes.byref(info), size) != size:
                raise OSError("cannot sample benchmark process")
            return info.wide[1]
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
        raise OSError("benchmark RSS unavailable")

    def run(self):
        while True:
            try:
                host, worker = (self.resident(pid) for pid in self.pids)
                self.samples.append(
                    {"host": host, "worker": worker, "total": host + worker}
                )
            except OSError as error:
                self.errors.append(type(error).__name__)
                return
            if self.stop.wait(0.02):
                return

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive() or self.errors or not self.samples:
            raise RuntimeError("memory sampling failed")


def child(args):
    import cigar_sdk
    from cigar_sdk import LocalContextBroker, LocalContextClient

    sdk = Path(cigar_sdk.__file__).parent
    sdk_hash = package_source_identity(
        (p.relative_to(sdk).as_posix(), p.read_bytes())
        for p in sdk.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and "_native" not in p.parts
    )
    documents = corpus(args.documents[0], args.payload_bytes)
    observations = {
        key: [] for key in ("open", "initial_admission", "replace", "compile", "close")
    }
    provenance = {
        "authority": "benchmark-host",
        "upstream_revision": "fixture",
        "observed_at_ms": 1,
        "valid_until_ms": None,
        "origin": "host",
        "derived_from": [],
    }

    def timed(name, operation, measured=True):
        start = time.perf_counter_ns()
        value = operation()
        if measured:
            observations[name].append((time.perf_counter_ns() - start) / 1e6)
        return value

    def grant(broker):
        return LocalContextClient(
            broker.grant(
                {
                    "id": "reader",
                    "policy_revision": "one",
                    "allowed_sources": ["cold", "hot"],
                },
                limits={"max_tickets": args.rounds + 4},
            )
        )

    own_before = resource.getrusage(resource.RUSAGE_SELF)
    worker_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="cigar-storage-probe-") as temporary:
        directory = Path(temporary) / "store"
        storage = (
            {"directory": str(directory), "create_directory": True}
            if args.mode == "sqlite"
            else None
        )
        broker = timed(
            "open",
            lambda: LocalContextBroker(
                "storage-probe", worker_path=args.worker, storage=storage, timeout=120
            ),
        )
        sampler = Sampler(broker._process.pid)
        sampler.thread.start()
        rendered = hashlib.sha256()
        disk_samples = []
        try:
            revision = broker.source_revision("cold")
            timed(
                "initial_admission",
                lambda: broker.replace_source("cold", revision, documents, provenance),
            )
            client = grant(broker)
            revision = broker.source_revision("hot")
            for iteration in range(args.rounds + 2):
                document = {
                    "id": "hot",
                    "source": "hot",
                    "text": f"Retry policy iteration {iteration}: stop after three attempts.",
                }
                receipt = timed(
                    "replace",
                    lambda: broker.replace_source(
                        "hot", revision, [document], provenance
                    ),
                    iteration >= 2,
                )
                revision = receipt["revision"]
                result = timed(
                    "compile",
                    lambda: client.compile(
                        {
                            "query": "retry policy",
                            "required": ["hot"],
                            "max_tokens": 512,
                        }
                    ),
                    iteration >= 2,
                )
                if document["text"] not in result["rendered"]:
                    raise RuntimeError("updated evidence missing")
                if result["context"]["snapshot"]["stats"]["rendered_tokens"] > 512:
                    raise RuntimeError("context budget exceeded")
                if iteration >= 2:
                    rendered.update(result["rendered"].encode())
                disk_samples.append(
                    sum(p.stat().st_size for p in directory.iterdir()) if storage else 0
                )
        finally:
            try:
                sampler.close()
            finally:
                timed("close", broker.close)
        if not broker.cleanup_complete:
            raise RuntimeError("broker cleanup incomplete")
        own_after = resource.getrusage(resource.RUSAGE_SELF)
        worker_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = {
            "host_ms": 1000
            * (
                own_after.ru_utime
                + own_after.ru_stime
                - own_before.ru_utime
                - own_before.ru_stime
            ),
            "worker_ms": 1000
            * (
                worker_after.ru_utime
                + worker_after.ru_stime
                - worker_before.ru_utime
                - worker_before.ru_stime
            ),
        }
        os_rss_scale = 1 if sys.platform == "darwin" else 1024
        resource_peaks = {
            "host_bytes": own_after.ru_maxrss * os_rss_scale,
            "worker_bytes": worker_after.ru_maxrss * os_rss_scale,
        }
        checkpoint_bytes = None
        resume_ms = None
        if storage:
            database = directory / "broker.sqlite3"
            with closing(
                sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
            ) as db:
                checkpoint_bytes = db.execute(
                    "SELECT length(checkpoint) FROM broker_meta WHERE id=1"
                ).fetchone()[0]
            start = time.perf_counter_ns()
            restored = LocalContextBroker(
                "storage-probe", worker_path=args.worker, storage=storage, timeout=120
            )
            resume_ms = (time.perf_counter_ns() - start) / 1e6
            with restored:
                current = restored.source_revision("hot")
                if (
                    current["version"] != revision["version"]
                    or current["epoch"] == revision["epoch"]
                ):
                    raise RuntimeError("recovery lost a revision or reused authority")
                result = grant(restored).compile(
                    {
                        "query": "retry policy",
                        "required": ["hot", documents[-1]["id"]],
                        "max_tokens": 2048,
                    }
                )
                if (
                    document["text"] not in result["rendered"]
                    or documents[-1]["text"] not in result["rendered"]
                ):
                    raise RuntimeError("recovery lost admitted evidence")
        return {
            "status": "ok",
            "mode": args.mode,
            "documents": len(documents),
            "payload_bytes": args.payload_bytes,
            "corpus_sha256": hashlib.sha256(encoded(documents)).hexdigest(),
            "worker_sha256": file_hash(args.worker),
            "sdk_source_sha256": sdk_hash,
            "python": platform.python_version(),
            "raw_ms": observations,
            "cpu": cpu,
            "rss_samples": sampler.samples,
            "os_peak_rss": resource_peaks,
            "disk_samples_bytes": disk_samples,
            "checkpoint_bytes": checkpoint_bytes,
            "resume_ms": resume_ms,
            "rendered_sha256": rendered.hexdigest(),
        }


def quantiles(values):
    ordered = sorted(values)
    return {
        "p50": statistics.median(ordered),
        "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "max": ordered[-1],
    }


def paired(values):
    """Resample whole paired process cohorts, never dependent calls."""
    differences = [candidate - baseline for baseline, candidate in values]
    relative = [
        candidate / baseline - 1 for baseline, candidate in values if baseline > 0
    ]
    interval = None
    if len(differences) >= 8:
        rng = random.Random(1400)
        draws = sorted(
            statistics.mean(rng.choices(differences, k=len(differences)))
            for _ in range(2000)
        )
        interval = [draws[49], draws[1949]]
    return {
        "cohorts": len(values),
        "mean_difference": statistics.mean(differences),
        "mean_relative_change": statistics.mean(relative)
        if len(relative) == len(values)
        else None,
        "difference_ci95": interval,
    }


def summarize(rows, counts, cohorts):
    summaries = {}
    for count in counts:
        selected = [row for row in rows if row["documents"] == count]
        if len(selected) != cohorts * 2 or any(
            row["status"] != "ok" for row in selected
        ):
            summaries[str(count)] = {"status": "incomplete", "paired": None}
            continue
        if any(
            len({row["rendered_sha256"] for row in selected if row["cohort"] == cohort})
            != 1
            for cohort in range(cohorts)
        ):
            raise ValueError("treatments returned different context")
        result = {"status": "ok", "timing": {}, "resources": {}, "paired": {}}
        for mode in ("memory", "sqlite"):
            group = [row for row in selected if row["mode"] == mode]
            result["timing"][mode] = {
                operation: quantiles(
                    [statistics.median(row["raw_ms"][operation]) for row in group]
                )
                for operation in group[0]["raw_ms"]
            }
            result["resources"][mode] = {
                "host_worker_sampled_rss_median_bytes": statistics.median(
                    max(x["total"] for x in row["rss_samples"]) for row in group
                ),
                "cpu_host_median_ms": statistics.median(
                    row["cpu"]["host_ms"] for row in group
                ),
                "cpu_worker_median_ms": statistics.median(
                    row["cpu"]["worker_ms"] for row in group
                ),
                "database_size_median_bytes": statistics.median(
                    max(row["disk_samples_bytes"]) for row in group
                ),
                "checkpoint_median_bytes": statistics.median(
                    row["checkpoint_bytes"] for row in group
                )
                if mode == "sqlite"
                else None,
                "resume_median_ms": statistics.median(row["resume_ms"] for row in group)
                if mode == "sqlite"
                else None,
            }
        for operation in ("replace", "compile"):
            values = []
            for cohort in range(cohorts):
                group = {
                    row["mode"]: row for row in selected if row["cohort"] == cohort
                }
                values.append(
                    tuple(
                        statistics.median(group[mode]["raw_ms"][operation])
                        for mode in ("memory", "sqlite")
                    )
                )
            result["paired"][operation] = paired(values)
        summaries[str(count)] = result
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=("memory", "sqlite"))
    parser.add_argument("--documents", nargs="+", type=int, default=[100, 1000, 5000])
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--cohorts", type=int, default=8)
    args = parser.parse_args()
    if (
        sys.platform not in ("darwin", "linux")
        or not args.worker.is_absolute()
        or not 1 <= args.rounds <= 64
        or not 1 <= args.cohorts <= 32
        or len(set(args.documents)) != len(args.documents)
        or any(not 1 <= count <= 10000 for count in args.documents)
        or not 128 <= args.payload_bytes <= 2048
    ):
        parser.error(
            "use an absolute worker, supported Unix host and bounded positive workload"
        )
    if args.mode:
        if len(args.documents) != 1:
            parser.error("a child measures one corpus")
        print(json.dumps(child(args), allow_nan=False))
        return
    if args.output is None:
        parser.error("--output is required")
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    harness = Path(__file__).read_bytes()
    helper = (root / "benchmarks/shared_views.py").read_bytes()
    worker_hash = file_hash(args.worker)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    plan = {
        "schema": "cigar.broker-storage-probe-plan.v1",
        "source_commit": commit,
        "worker_sha256": worker_hash,
        "worker_bytes": args.worker.stat().st_size,
        "harness_sha256": hashlib.sha256(harness).hexdigest(),
        "helper_sha256": hashlib.sha256(helper).hexdigest(),
        "host": platform.platform(),
        "python": sys.version,
        "cohorts": args.cohorts,
        "documents": args.documents,
        "payload_bytes": args.payload_bytes,
        "rounds": args.rounds,
        "warmup_rounds": 2,
        "treatments": ["memory", "sqlite"],
        "order": "alternating within paired process cohorts",
        "model_mode": "none",
        "network_policy": "local loopback only by implementation; no OS deny claim",
        "acceptance": "diagnostic only; no release-performance or version-comparison acceptance",
        "measurement": "Source SDK, explicit worker (bundled hashing excluded), 20ms RSS sampler. "
        "Call p50/p95 remain descriptive. Intervals resample process medians. CPU excludes recovery. "
        "Disk sizes are retained file bytes after calls, not peak journal bytes or bytes written.",
    }
    (args.output / "plan.json").write_bytes(encoded(plan))
    (args.output / "broker_storage.py").write_bytes(harness)
    (args.output / "shared_views.py").write_bytes(helper)
    rows = []
    for count in args.documents:
        corpus_bytes = encoded(corpus(count, args.payload_bytes))
        (args.output / f"corpus-{count}.json").write_bytes(corpus_bytes)
        for cohort in range(args.cohorts):
            for mode in (
                ("memory", "sqlite") if cohort % 2 == 0 else ("sqlite", "memory")
            ):
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    str(args.worker),
                    "--mode",
                    mode,
                    "--documents",
                    str(count),
                    "--rounds",
                    str(args.rounds),
                    "--payload-bytes",
                    str(args.payload_bytes),
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
                    error = "benchmark child exceeded 300-second deadline"
                if error is not None:
                    (args.output / f"failure-{count}-{cohort}-{mode}.txt").write_text(
                        error
                    )
                    row = {"status": "failed", "documents": count, "mode": mode}
                else:
                    row = json.loads(process.stdout)
                    if row["worker_sha256"] != worker_hash:
                        raise RuntimeError("worker changed during study")
                    if (
                        row["corpus_sha256"] != hashlib.sha256(corpus_bytes).hexdigest()
                        or row["documents"] != count
                        or row["mode"] != mode
                        or row["payload_bytes"] != args.payload_bytes
                    ):
                        raise RuntimeError("child measured a different workload")
                rows.append({"cohort": cohort, **row})
                with (args.output / "observations.jsonl").open("ab") as handle:
                    handle.write(encoded(rows[-1]))
            print(f"{count} documents: cohort {cohort + 1}/{args.cohorts}", flush=True)
    if (
        file_hash(args.worker) != worker_hash
        or Path(__file__).read_bytes() != harness
        or (root / "benchmarks/shared_views.py").read_bytes() != helper
    ):
        raise RuntimeError("study inputs changed")
    successful = [row for row in rows if row["status"] == "ok"]
    if len({row["sdk_source_sha256"] for row in successful}) != 1:
        raise RuntimeError("SDK sources changed")
    result = {
        "schema": "cigar.broker-storage-probe.v1",
        "plan": plan,
        "summary": summarize(rows, args.documents, args.cohorts),
    }
    (args.output / "result.json").write_bytes(encoded(result))
    print(json.dumps(result["summary"], indent=2))
    if len(successful) != len(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
