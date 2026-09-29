"""Offline source-ingestion study: whole-frame versus bounded batches, same worker.

Logical source size, acknowledged receipts and exact selected text are invariants.
This compares two APIs, not released versions or model efficacy. Input reading,
JSON decoding/encoding and all ingestion calls are in the end-to-end measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

from broker_storage import Sampler, encoded, file_hash, paired, quantiles
from shared_views import package_source_identity

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = 256 * 1024
PER_BATCH = 4
PROVENANCE = {
    "authority": "fixture-host",
    "upstream_revision": "one",
    "observed_at_ms": 1,
    "valid_until_ms": None,
    "origin": "host",
    "derived_from": [],
}
PROBE = {
    "id": "probe",
    "source": "docs",
    "text": "Retry policy: stop after three attempts.",
}


def documents(mib):
    for index in range(mib * 4):
        prefix = f"Archive record {index:06d}. "
        text = (prefix + "Archived material. " * (PAYLOAD // 19 + 1))[:PAYLOAD]
        yield {"id": f"cold-{index}", "source": "docs", "text": text}
    yield PROBE


def read_documents(path):
    with path.open("rb") as stream:
        for line in stream:
            yield json.loads(line)


def batches(values):
    batch = []
    for document in values:
        batch.append(document)
        if len(batch) == PER_BATCH:
            yield batch
            batch = []
    if batch:
        yield batch


def sdk_identity():
    import cigar_sdk

    root = Path(cigar_sdk.__file__).parent
    return package_source_identity(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and "_native" not in path.parts
    )


def child(args):
    from cigar_sdk import LocalBrokerError, LocalContextBroker, LocalContextClient

    identity = sdk_identity()
    worker_hash = file_hash(args.worker)
    corpus_hash = file_hash(args.corpus)
    phases, frames = {}, []
    measuring = False
    storage = None
    with tempfile.TemporaryDirectory(prefix="cigar-ingestion-") as temporary:
        if args.storage == "sqlite":
            storage = {
                "directory": str(Path(temporary) / "store"),
                "create_directory": True,
                "max_checkpoint_bytes": 64 * 1024 * 1024,
                "max_database_bytes": 256 * 1024 * 1024,
            }
        options = {
            "worker_path": args.worker,
            "timeout": 120,
            "storage": storage,
            "graph": {
                "max_documents": 10000,
                "max_document_bytes": PAYLOAD,
                "max_total_bytes": 64 * 1024 * 1024,
            },
            "retention": {"max_retained_bytes": 64 * 1024 * 1024},
        }
        start = time.perf_counter_ns()
        broker = LocalContextBroker("ingestion-probe", **options)
        open_ms = (time.perf_counter_ns() - start) / 1e6
        try:
            before = broker.replace_source(
                "docs",
                broker.source_revision("docs"),
                [
                    {
                        "id": "obsolete",
                        "source": "docs",
                        "text": "Old evidence remains until commit.",
                    },
                ],
                PROVENANCE,
            )["revision"]
            original_call = broker._call
            original_send = broker._jobs.put_nowait

            def call(command):
                start = time.perf_counter_ns()
                try:
                    return original_call(command)
                finally:
                    if measuring:
                        phases.setdefault(command["op"], []).append(
                            (time.perf_counter_ns() - start) / 1e6
                        )

            def send(job):
                if measuring and job is not None:
                    frames.append(len(job[0]))
                return original_send(job)

            broker._call = call
            broker._jobs.put_nowait = send
            sampler = Sampler(broker._process.pid)
            sampler.thread.start()
            try:
                start = time.perf_counter_ns()
                measuring = True
                receipt, rejected = None, None
                try:
                    values = read_documents(args.corpus)
                    if args.mode == "whole":
                        receipt = broker.replace_source(
                            "docs", before, list(values), PROVENANCE
                        )
                    else:
                        receipt = broker.replace_source_batches(
                            "docs",
                            before,
                            batches(values),
                            PROVENANCE,
                            lease_ms=120_000,
                        )
                except LocalBrokerError as error:
                    if (
                        args.mode != "whole"
                        or args.mib <= 32
                        or error.code != "LimitExceeded"
                        or error.dispatched is not False
                    ):
                        raise
                    rejected = {"code": error.code, "dispatched": error.dispatched}
                finally:
                    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                    measuring = False
            finally:
                sampler.close()
            if args.mode == "whole" and args.mib > 32:
                if (
                    rejected is None
                    or receipt is not None
                    or frames
                    or broker.source_revision("docs") != before
                ):
                    raise RuntimeError(
                        "oversized single-frame call did not fail before dispatch"
                    )
            elif rejected is not None or receipt != {
                "revision": {"epoch": before["epoch"], "version": "2"},
                "inserted": args.mib * 4 + 1,
                "replaced": 0,
                "removed": 1,
                "unchanged": 0,
            }:
                raise RuntimeError("source replacement receipt mismatch")

            def verify(owner, revision):
                client = LocalContextClient(
                    owner.grant(
                        {
                            "id": "reader",
                            "allowed_sources": ["docs"],
                            "policy_revision": "one",
                        }
                    )
                )
                result = client.compile(
                    {
                        "query": "retry policy",
                        "required": ["probe"] if receipt else ["obsolete"],
                        "max_tokens": 512,
                    }
                )
                snapshot = result["context"]["snapshot"]
                selected = {
                    citation["node_id"]
                    for block in snapshot["blocks"]
                    for citation in block["citations"]
                }
                if (
                    selected != ({"probe"} if receipt else {"obsolete"})
                    or snapshot["stats"]["documents"]
                    != (args.mib * 4 + 1 if receipt else 1)
                    or snapshot["stats"]["rendered_tokens"] > 512
                    or owner.source_revision("docs")["version"] != revision["version"]
                ):
                    raise RuntimeError(
                        "compiled graph did not match complete old/new source"
                    )
                return hashlib.sha256(result["rendered"].encode()).hexdigest()

            revision = receipt["revision"] if receipt else before
            rendered_hash = verify(broker, revision)
        finally:
            start = time.perf_counter_ns()
            broker.close()
            close_ms = (time.perf_counter_ns() - start) / 1e6
        if not broker.cleanup_complete:
            raise RuntimeError("worker cleanup incomplete")
        resume_ms = None
        if storage:
            start = time.perf_counter_ns()
            with LocalContextBroker("ingestion-probe", **options) as restored:
                resume_ms = (time.perf_counter_ns() - start) / 1e6
                if (
                    restored.source_revision("docs")["epoch"] == before["epoch"]
                    or verify(restored, revision) != rendered_hash
                ):
                    raise RuntimeError("recovery reused authority or lost evidence")
        if (
            worker_hash != file_hash(args.worker)
            or corpus_hash != file_hash(args.corpus)
            or identity != sdk_identity()
        ):
            raise RuntimeError("input bytes changed during measurement")
        return {
            "status": "ok",
            "outcome": "committed" if receipt else "rejected_before_dispatch",
            "mode": args.mode,
            "storage": args.storage,
            "mib": args.mib,
            "worker_sha256": worker_hash,
            "corpus_sha256": corpus_hash,
            "sdk_source_sha256": identity,
            "input_to_ack_ms": elapsed_ms,
            "phases_ms": phases,
            "sent_frames_bytes": frames,
            "rss_samples": sampler.samples,
            "open_ms": open_ms,
            "close_ms": close_ms,
            "resume_ms": resume_ms,
            "rendered_sha256": rendered_hash,
            "rejected": rejected,
            "receipt": {
                key: value for key, value in receipt.items() if key != "revision"
            }
            if receipt
            else None,
        }


def summarize(rows, sizes, cohorts):
    expected = {
        (size, storage, mode, cohort)
        for size in sizes
        for storage in ("memory", "sqlite")
        for mode in ("whole", "batches")
        for cohort in range(cohorts)
    }
    indexed = {
        (row["mib"], row["storage"], row["mode"], row["cohort"]): row for row in rows
    }
    if set(indexed) != expected or len(rows) != len(expected):
        raise ValueError("missing, extra or duplicate ingestion cohort")
    result = {}
    for size in sizes:
        for storage in ("memory", "sqlite"):
            group = [
                indexed[size, storage, mode, cohort]
                for mode in ("whole", "batches")
                for cohort in range(cohorts)
            ]
            name = f"{size}MiB/{storage}"
            if any(row["status"] != "ok" for row in group):
                result[name] = {"status": "incomplete", "paired": None}
                continue
            for mode in ("whole", "batches"):
                expected_outcome = (
                    "rejected_before_dispatch"
                    if size > 32 and mode == "whole"
                    else "committed"
                )
                selected = [row for row in group if row["mode"] == mode]
                if (
                    any(row["outcome"] != expected_outcome for row in selected)
                    or len({row["rendered_sha256"] for row in selected}) != 1
                ):
                    raise ValueError(
                        "ingestion outcome or deterministic rendering differs"
                    )
            if len({row["corpus_sha256"] for row in group}) != 1:
                raise ValueError("paired ingestion inputs differ")
            if size <= 32 and len({row["rendered_sha256"] for row in group}) != 1:
                raise ValueError("whole and batch APIs compiled different evidence")
            measurements = {
                "input_to_ack_ms": lambda row: row["input_to_ack_ms"],
                "sampled_host_worker_rss_bytes": lambda row: max(
                    sample["total"] for sample in row["rss_samples"]
                ),
                "sampled_host_rss_bytes": lambda row: max(
                    sample["host"] for sample in row["rss_samples"]
                ),
            }
            metrics = {}
            for metric, measure in measurements.items():
                values = [
                    (
                        measure(indexed[size, storage, "whole", cohort]),
                        measure(indexed[size, storage, "batches", cohort]),
                    )
                    for cohort in range(cohorts)
                ]
                metrics[metric] = {
                    "whole": quantiles([a for a, _ in values]),
                    "batches": quantiles([b for _, b in values]),
                    "paired": paired(values) if size <= 32 else None,
                }
            result[name] = {
                "status": "comparable" if size <= 32 else "frame_boundary_demonstrated",
                "metrics": metrics,
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1, 8, 34])
    parser.add_argument("--cohorts", type=int, default=8)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--mib", type=int)
    parser.add_argument("--mode", choices=["whole", "batches"])
    parser.add_argument("--storage", choices=["memory", "sqlite"])
    args = parser.parse_args()
    if args.child:
        print(json.dumps(child(args)))
        return
    if (
        not args.worker.is_absolute()
        or not args.output.is_absolute()
        or not 1 <= args.cohorts <= 16
        or len(set(args.sizes)) != len(args.sizes)
        or any(size not in (1, 8, 34) for size in args.sizes)
    ):
        parser.error(
            "use an absolute worker, 1..16 cohorts and unique 1/8/34 MiB sizes"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    sources = {
        name: (ROOT / "benchmarks" / name).read_bytes()
        for name in ("broker_ingestion.py", "broker_storage.py", "shared_views.py")
    }
    worker = args.output / "worker"
    shutil.copy2(args.worker, worker)
    worker_hash = file_hash(worker)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    patch = subprocess.check_output(
        [
            "git",
            "diff",
            "--binary",
            "HEAD",
            "--",
            "crates/cigar-context",
            "sdk/python/src/cigar_sdk",
        ],
        cwd=ROOT,
    )
    (args.output / "tracked.patch").write_bytes(patch)
    untracked = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            "crates/cigar-context",
            "sdk/python/src/cigar_sdk",
        ],
        cwd=ROOT,
        text=True,
    ).splitlines()
    for name in untracked:
        target = args.output / "untracked" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    for name, payload in sources.items():
        (args.output / name).write_bytes(payload)
    plan = {
        "schema": "cigar.broker-ingestion-plan.v1",
        "worker_sha256": worker_hash,
        "source_commit": commit,
        "tracked_patch_sha256": hashlib.sha256(patch).hexdigest(),
        "untracked_source": {name: file_hash(ROOT / name) for name in untracked},
        "harnesses": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sources.items()
        },
        "sizes_mib": args.sizes,
        "cohorts": args.cohorts,
        "python": sys.version,
        "host": platform.platform(),
        "batch_documents": PER_BATCH,
        "document_text_bytes": PAYLOAD,
        "model_mode": "none",
        "scope": "Same candidate worker/SDK, additive API comparison. File read/JSON parse/encode and all ingestion calls timed. "
        "RSS sampled every 20ms only during input-to-ack; not PSS or exact peaks. Explicit worker excludes bundled hashing. "
        "Fresh processes, order reversed on odd cohorts. No speed ratio between rejected and committed operations. "
        "Literal loopback only by implementation; no OS network-denial or installed-release qualification claim.",
    }
    (args.output / "plan.json").write_bytes(encoded(plan))
    rows = []
    for size in args.sizes:
        corpus = args.output / f"corpus-{size}.jsonl"
        with corpus.open("xb") as stream:
            for document in documents(size):
                stream.write(encoded(document))
        corpus_hash = file_hash(corpus)
        for cohort in range(args.cohorts):
            order = [
                (storage, mode)
                for storage in ("memory", "sqlite")
                for mode in ("whole", "batches")
            ]
            for storage, mode in order if cohort % 2 == 0 else reversed(order):
                row = {
                    "status": "failed",
                    "mib": size,
                    "storage": storage,
                    "mode": mode,
                    "cohort": cohort,
                }
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--child",
                    "--worker",
                    str(worker),
                    "--output",
                    str(args.output),
                    "--corpus",
                    str(corpus),
                    "--mib",
                    str(size),
                    "--storage",
                    storage,
                    "--mode",
                    mode,
                ]
                try:
                    run = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=240,
                        env={**os.environ, "PYTHONPATH": str(ROOT / "sdk/python/src")},
                    )
                    if run.returncode:
                        raise RuntimeError(run.stderr)
                    value = json.loads(run.stdout)
                    if (
                        value["worker_sha256"] != worker_hash
                        or value["corpus_sha256"] != corpus_hash
                        or any(value[k] != row[k] for k in ("mib", "storage", "mode"))
                    ):
                        raise RuntimeError("ingestion input identity changed")
                    row = {**value, "cohort": cohort}
                except (subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
                    (
                        args.output / f"failure-{size}-{storage}-{mode}-{cohort}.txt"
                    ).write_text(str(error))
                rows.append(row)
                with (args.output / "observations.jsonl").open("ab") as stream:
                    stream.write(encoded(row))
            print(f"{size} MiB: cohort {cohort + 1}/{args.cohorts}", flush=True)
    if file_hash(worker) != worker_hash or any(
        (ROOT / "benchmarks" / name).read_bytes() != payload
        for name, payload in sources.items()
    ):
        raise RuntimeError("worker/harness changed during study")
    successful = [row for row in rows if row["status"] == "ok"]
    if len({row["sdk_source_sha256"] for row in successful}) > 1:
        raise RuntimeError("SDK changed during study")
    summary = summarize(rows, args.sizes, args.cohorts)
    (args.output / "result.json").write_bytes(
        encoded(
            {"schema": "cigar.broker-ingestion.v1", "plan": plan, "summary": summary}
        )
    )
    print(json.dumps(summary, indent=2))
    if len(successful) != len(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
