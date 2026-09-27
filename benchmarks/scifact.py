"""Offline SciFact ingestion and prediction, deliberately separate from gold scoring.

The preregistered development split is held out for this library study, not the
official hidden test set. This harness makes no model/provider call. Dataset
acquisition is a separate action; untrusted archive members are never extracted
or executed. Run one consumer process per treatment and token budget.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile
import threading
import time

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "benches/context-evaluation")
)
from evaluation import decode, encoded, file_digest, require  # noqa: E402


CONFIG = {
    "schema": "cigar.scifact-configuration.v1",
    "split": "claims_dev.jsonl",
    "budgets": [512, 2048, 4096],
    "rank_limit": 64,
    "request": {
        "reserve_tokens": 0,
        "required": [],
        "max_candidates": 256,
        "max_blocks": 16,
        "graph_depth": 2,
        "evidence_per_term": 1,
        "excerpt_mode": "full",
        "policy_revision": "scifact-abstracts.v1",
    },
    "domain": "cigar-scifact-abstracts.v1",
    "text": "title + LF + original abstract sentences joined with LF",
    "ingestion_order": "numeric doc_id ascending",
    "flat_control": "longest BM25 prefix fitting exact v0.12 rendered budget",
    "flat_empty_query": "scifact-empty-prefix",
    "source": "https://scifact.s3-us-west-2.amazonaws.com/release/latest/data.tar.gz",
    "seed": 140014,
}
MAX_ARCHIVE = 32 * 1024**2
MAX_TAR = 128 * 1024**2


def json_lines(data: bytes) -> list[dict]:
    require(len(data) <= 64 * 1024**2, "dataset input too large")
    rows = []
    for line in data.splitlines():
        require(0 < len(line) <= 1024**2, "invalid dataset line size")
        row = decode(line)
        require(type(row) is dict, "invalid dataset record")
        rows.append(row)
        require(len(rows) <= 100_000, "too many dataset records")
    require(bool(rows), "empty dataset input")
    return rows


def archive_members(path: Path) -> dict[str, bytes]:
    require(0 < path.stat().st_size <= MAX_ARCHIVE, "archive byte limit exceeded")
    with gzip.open(path, "rb") as stream:
        data = stream.read(MAX_TAR + 1)
    require(len(data) <= MAX_TAR, "archive expansion limit exceeded")
    selected, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for index, member in enumerate(archive):
            require(index < 100, "archive member limit exceeded")
            name = PurePosixPath(member.name)
            require(
                not name.is_absolute()
                and ".." not in name.parts
                and "\\" not in member.name
                and member.name not in seen,
                "unsafe or duplicate archive member",
            )
            seen.add(member.name)
            if member.isdir():
                continue
            require(
                member.isfile() and member.size <= 64 * 1024**2,
                "invalid archive member",
            )
            if name.name in {
                "corpus.jsonl",
                "claims_dev.jsonl",
                "claims_train.jsonl",
                "claims_test.jsonl",
            }:
                require(name.name not in selected, "duplicate dataset file")
                stream = archive.extractfile(member)
                require(stream is not None, "missing dataset member")
                payload = stream.read(member.size + 1)
                require(len(payload) == member.size, "truncated dataset member")
                selected[name.name] = payload
    require(
        set(selected)
        == {
            "corpus.jsonl",
            "claims_dev.jsonl",
            "claims_train.jsonl",
            "claims_test.jsonl",
        },
        "incomplete dataset archive",
    )
    return selected


def positive_id(value: object) -> bool:
    return type(value) is int and 0 < value < 2**53


def prepare(archive: Path, output: Path) -> dict:
    require(not output.exists(), "dataset destination already exists")
    members = archive_members(archive)
    documents, seen = [], set()
    for row in json_lines(members["corpus.jsonl"]):
        require(
            set(row) == {"doc_id", "title", "abstract", "structured"},
            "invalid corpus fields",
        )
        require(
            positive_id(row["doc_id"]) and row["doc_id"] not in seen,
            "duplicate or invalid paper ID",
        )
        require(
            type(row["title"]) is str and type(row["structured"]) is bool,
            "invalid paper metadata",
        )
        require(
            type(row["abstract"]) is list
            and all(type(s) is str for s in row["abstract"]),
            "invalid abstract",
        )
        seen.add(row["doc_id"])
        documents.append(
            {
                "id": str(row["doc_id"]),
                "source": "scifact",
                "text": row["title"] + "\n" + "\n".join(row["abstract"]),
                "start_line": 1,
            }
        )
    documents.sort(key=lambda row: int(row["id"]))
    require(len(documents) <= 100_000, "corpus document limit exceeded")
    queries, splits = [], {}
    for name in ("claims_train.jsonl", "claims_dev.jsonl", "claims_test.jsonl"):
        ids = set()
        for row in json_lines(members[name]):
            require(
                positive_id(row.get("id"))
                and row["id"] not in ids
                and type(row.get("claim")) is str,
                "invalid claim identity",
            )
            ids.add(row["id"])
            if name == CONFIG["split"]:
                # Gold values are neither inspected nor passed to the consumer.
                require(
                    set(row) == {"id", "claim", "evidence", "cited_doc_ids"},
                    "invalid development fields",
                )
                queries.append({"id": f"claim-{row['id']}", "query": row["claim"]})
        splits[name] = ids
    require(
        not any(splits[a] & splits[b] for a in splits for b in splits if a < b),
        "claim IDs overlap across splits",
    )
    queries.sort(key=lambda row: int(row["id"].removeprefix("claim-")))
    output.mkdir(mode=0o700)
    payloads = {
        "corpus.jsonl": b"".join(encoded(row) for row in documents),
        "queries.jsonl": b"".join(encoded(row) for row in queries),
        "oracle.jsonl": members[CONFIG["split"]],
        "original-corpus.jsonl": members["corpus.jsonl"],
    }
    metadata = {
        "schema": "cigar.scifact-inputs.v1",
        "archive_sha256": file_digest(archive),
        "archive_bytes": archive.stat().st_size,
        "source": CONFIG["source"],
        "documents": len(documents),
        "queries": len(queries),
        "split_counts": {name: len(ids) for name, ids in splits.items()},
        "claim_id_overlap": False,
        "configuration": CONFIG,
        "harness_sha256": file_digest(Path(__file__)),
        "files": {},
        "licenses": {
            "annotations": "CC-BY-4.0",
            "abstracts": "ODC-By-1.0 (S2ORC)",
            "notice": "https://github.com/allenai/scifact/blob/master/LICENSE.md",
        },
    }
    for name, data in payloads.items():
        (output / name).write_bytes(data)
        metadata["files"][name] = hashlib.sha256(data).hexdigest()
    (output / "inputs.json").write_bytes(encoded(metadata))
    return metadata


def source_identity(root: Path) -> str:
    rows = []
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if (
            path.is_file()
            and "_native" not in parts
            and "__pycache__" not in parts
            and path.suffix != ".pyc"
        ):
            require(not path.is_symlink(), "SDK source cannot contain symlinks")
            rows.append([path.relative_to(root).as_posix(), file_digest(path)])
    require(bool(rows), "empty SDK source inventory")
    return hashlib.sha256(
        json.dumps(sorted(rows), separators=(",", ":")).encode()
    ).hexdigest()


def load_recipe(path: Path):
    spec = importlib.util.spec_from_file_location("scifact_scoped_recipe", path)
    require(spec is not None and spec.loader is not None, "missing recipe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class MemorySamples:
    """macOS/Linux ps RSS sums at 50 ms; neither PSS nor instantaneous peaks."""

    def __init__(self, worker_pid: int):
        self.pids = (os.getpid(), worker_pid)
        self.rows = []
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        try:
            while not self.done.is_set():
                reply = subprocess.run(
                    ["/bin/ps", "-o", "pid=,rss=", "-p", ",".join(map(str, self.pids))],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
                rows = {
                    int(p): int(r) * 1024
                    for p, r in (line.split() for line in reply.stdout.splitlines())
                }
                require(set(rows) == set(self.pids), "RSS process missing")
                self.rows.append(
                    {
                        "monotonic_ns": time.monotonic_ns(),
                        "host": rows[self.pids[0]],
                        "worker": rows[self.pids[1]],
                        "total": sum(rows.values()),
                    }
                )
                self.done.wait(0.05)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.error = type(error).__name__

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.done.set()
        self.thread.join(timeout=6)
        require(
            not self.thread.is_alive() and bool(self.rows) and self.error is None,
            "RSS sampler incomplete",
        )


def request(query: str, budget: int) -> dict:
    return {**CONFIG["request"], "required": [], "query": query, "max_tokens": budget}


def flat_prefix(
    graph, predicted: list[str], budget: int, error_type
) -> tuple[dict, int]:
    """Use only predicted IDs, never gold, with the released exact renderer."""
    selected, calls = [], 1
    # The API rejects empty query plus empty required IDs. This fixed query with
    # an explicitly empty authorization set produces the valid empty control.
    result = graph.compile(
        {**request(CONFIG["flat_empty_query"], budget), "allowed": []}
    )
    for node_id in predicted[: CONFIG["request"]["max_blocks"]]:
        trial = [*selected, node_id]
        calls += 1
        try:
            next_result = graph.compile(
                {**request("", budget), "allowed": trial, "required": trial}
            )
        except error_type as error:
            if error.code == "BudgetUnsatisfiable":
                break
            raise
        selected, result = trial, next_result
    return result, calls


def consume(
    data: Path,
    identity_path: Path,
    recipe_path: Path,
    worker: Path,
    mode: str,
    budget: int,
    output: Path,
) -> dict:
    require(
        not output.exists()
        and mode in {"default", "ranked", "flat"}
        and budget in CONFIG["budgets"],
        "invalid consumer destination or treatment",
    )
    import cigar_sdk
    from cigar_sdk import LocalContextError, LocalContextGraph

    identity = decode(identity_path.read_bytes())
    metadata = decode((data / "inputs.json").read_bytes())
    sdk_root = Path(cigar_sdk.__file__).resolve().parent
    require(metadata["configuration"] == CONFIG, "configuration mismatch")
    require(
        identity["sdk_source_sha256"] == source_identity(sdk_root),
        "SDK source identity mismatch",
    )
    require(
        identity["worker_sha256"] == file_digest(worker), "worker identity mismatch"
    )
    require(
        identity["recipe_sha256"] == file_digest(recipe_path),
        "recipe identity mismatch",
    )
    require(
        identity["harness_sha256"] == file_digest(Path(__file__)),
        "harness identity mismatch",
    )
    for name in ("corpus.jsonl", "queries.jsonl"):
        require(
            metadata["files"][name] == file_digest(data / name),
            "input identity mismatch",
        )
    documents = json_lines((data / "corpus.jsonl").read_bytes())
    queries = json_lines((data / "queries.jsonl").read_bytes())
    require(
        len(documents) == metadata["documents"] and len(queries) == metadata["queries"],
        "input inventory mismatch",
    )
    require(
        all(set(row) == {"id", "query"} for row in queries),
        "consumer query includes non-query fields",
    )
    output.mkdir(mode=0o700)
    start = time.perf_counter_ns()
    graph = LocalContextGraph(CONFIG["domain"], worker_path=worker, timeout=120)
    startup_ms = (time.perf_counter_ns() - start) / 1e6
    try:
        with MemorySamples(graph._process.pid) as memory:
            start = time.perf_counter_ns()
            graph.replace_source("scifact", documents)
            ingestion_ms = (time.perf_counter_ns() - start) / 1e6
            start = time.perf_counter_ns()
            ranker = None
            if mode != "default":
                recipe = load_recipe(recipe_path)
                records = {
                    row["id"]: recipe.RetrievalDocument(
                        row["id"],
                        row["source"],
                        metadata["files"]["corpus.jsonl"],
                        row["text"],
                    )
                    for row in documents
                }
                ranker = recipe.ScopedBM25(
                    recipe.ScopedCorpus(
                        records,
                        allowed=list(records),
                        policy_revision=CONFIG["request"]["policy_revision"],
                    )
                )
            index_ms = (time.perf_counter_ns() - start) / 1e6
            count, failures = 0, 0
            with (output / "predictions.jsonl").open("xb") as stream:
                for query in queries:
                    start = time.perf_counter_ns()
                    predicted = (
                        ranker.rank(query["query"], limit=CONFIG["rank_limit"])
                        if ranker
                        else []
                    )
                    ranking_ms = (time.perf_counter_ns() - start) / 1e6
                    start = time.perf_counter_ns()
                    result, error, calls = None, None, 1
                    try:
                        if mode == "flat":
                            result, calls = flat_prefix(
                                graph, predicted, budget, LocalContextError
                            )
                        else:
                            value = request(query["query"], budget)
                            if mode == "ranked":
                                value["semantic_candidates"] = predicted
                            result = graph.compile(value)
                    except LocalContextError as exception:
                        error = exception.code
                        failures += 1
                    compile_ms = (time.perf_counter_ns() - start) / 1e6
                    # Integrity checking is outside measured query latency.
                    if result is not None:
                        require(
                            graph.verify(result["snapshot"]) == result,
                            "snapshot rendering verification failed",
                        )
                    stream.write(
                        encoded(
                            {
                                "id": query["id"],
                                "status": "failed" if error else "ok",
                                "error": error,
                                "ranked_ids": predicted,
                                "result": result,
                                "ranking_ms": ranking_ms,
                                "compile_ms": compile_ms,
                                "compile_calls": calls,
                            }
                        )
                    )
                    count += 1
        require(count == len(queries), "incomplete prediction inventory")
    finally:
        graph.close()
    require(
        identity["sdk_source_sha256"] == source_identity(sdk_root)
        and identity["worker_sha256"] == file_digest(worker),
        "runtime changed during study",
    )
    summary = {
        "schema": "cigar.scifact-predictions.v1",
        "identity": identity,
        "inputs_sha256": file_digest(data / "inputs.json"),
        "mode": mode,
        "budget": budget,
        "python": platform.python_version(),
        "protobuf": importlib.metadata.version("protobuf"),
        "platform": platform.platform(),
        "queries": count,
        "failures": failures,
        "startup_ms": startup_ms,
        "ingestion_ms": ingestion_ms,
        "index_ms": index_ms,
        "predictions_sha256": file_digest(output / "predictions.jsonl"),
        "rss_samples": memory.rows,
    }
    (output / "summary.json").write_bytes(encoded(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--archive", required=True, type=Path)
    prep.add_argument("--output", required=True, type=Path)
    run = commands.add_parser("consume")
    for name in ("data", "identity", "recipe", "worker", "output"):
        run.add_argument(f"--{name}", required=True, type=Path)
    run.add_argument("--mode", required=True, choices=("default", "ranked", "flat"))
    run.add_argument("--budget", required=True, type=int)
    args = parser.parse_args()
    if args.command == "prepare":
        value = prepare(args.archive, args.output)
        print(
            encoded(
                {
                    "documents": value["documents"],
                    "queries": value["queries"],
                    "archive_sha256": value["archive_sha256"],
                }
            ).decode(),
            end="",
        )
    else:
        value = consume(
            args.data,
            args.identity,
            args.recipe,
            args.worker,
            args.mode,
            args.budget,
            args.output,
        )
        print(
            encoded(
                {
                    "queries": value["queries"],
                    "failures": value["failures"],
                    "predictions_sha256": value["predictions_sha256"],
                }
            ).decode(),
            end="",
        )


if __name__ == "__main__":
    main()
