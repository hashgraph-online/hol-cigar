#!/usr/bin/env python3
"""Export compact results and representative transcripts; inventory all originals."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

from worker import canonical


def read(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sequences = args.output / "response-sequences"
    sequences.mkdir()
    cohorts = {"primary": "evaluation-2", "working-set-768": "cache-pressure",
               "working-set-1536": "cache-pressure-1536", "working-set-3072": "cache-pressure-3072"}
    inventory, archive, summaries, bindings = {}, {}, {}, {}
    for label, directory in cohorts.items():
        source = args.results_root / directory
        assert read(source / "status.json")["status"] == "passed"
        destination = args.output / label
        destination.mkdir()
        for path in source.glob("*.json"):
            shutil.copyfile(path, destination / path.name)
        shutil.copytree(source / "inputs", destination / "inputs")
        (destination / "performance").mkdir()
        shutil.copyfile(source / "performance/summary.json", destination / "performance/summary.json")
        summaries[label] = read(source / "performance/summary.json")
        manifest = read(source / "manifest.json")["files"]
        records = []
        for path in sorted((source / "performance").glob("*.json")):
            if path.name == "summary.json":
                continue
            record = read(path)
            sequence = record.pop("complete_response_digests")
            raw = canonical(sequence)
            identity = hashlib.sha256(raw).hexdigest()
            path_out = sequences / f"{identity}.json.gz"
            if not path_out.exists():
                path_out.write_bytes(gzip.compress(raw, mtime=0))
            record.update({"response_sequence_sha256": identity, "response_count": len(sequence),
                           "original_relative_path": str(path.relative_to(source)), "original_sha256": sha(path)})
            records.append(record)
        (destination / "performance/session-records.jsonl.gz").write_bytes(gzip.compress(b"".join(canonical(r) + b"\n" for r in records), mtime=0))
        traces = list((source / "performance").glob("*-00-*.trace.jsonl.gz")) + list(source.glob("capability-*.jsonl.gz"))
        if (source / "answers").is_dir():
            (destination / "answers").mkdir()
            shutil.copyfile(source / "answers/summary.json", destination / "answers/summary.json")
            (destination / "answers/episodes.jsonl.gz").write_bytes(gzip.compress((source / "answers/episodes.jsonl").read_bytes(), mtime=0))
            traces.extend((source / "answers").glob("*.jsonl.gz"))
        for path in sorted(traces):
            relative = str(path.relative_to(source))
            assert sha(path) == manifest[relative]["sha256"]
            archive[f"{label}/{relative}"] = path
            inventory[f"{label}/{relative}"] = manifest[relative]
        bindings[label] = {"original_root": str(source.resolve()), "manifest": f"{label}/manifest.json", "original_files": len(manifest)}
    with (args.output / "representative-transcripts.tar.gz").open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for name, path in sorted(archive.items()):
                    raw = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(raw), 0o644, 0
                    tar.addfile(info, io.BytesIO(raw))
    write(args.output / "transcript-manifest.json", inventory)
    shutil.copyfile(args.results_root / "verification.json", args.output / "independent-verification.json")
    build = args.results_root / "build"
    shutil.copyfile(build / "build.json", args.output / "build.json")
    for label in ("baseline", "candidate"):
        destination = args.output / "build" / label
        destination.mkdir(parents=True)
        for name in ("Cargo.toml", "Cargo.lock", "build.log", "lock.log"):
            shutil.copyfile(build / label / name, destination / name)
    shutil.copytree(args.results_root / "evaluation-1", args.output / "diagnostic-invalid-capability-query")
    write(args.output / "retention.json", {
        "cohorts": bindings, "representative_transcripts": len(inventory),
        "all_answer_transcripts_included": True,
        "performance_transcript_selection": "First campaign pair for every workload/cache mode; all other complete transcripts remain at original paths and are hash-inventoried. All per-session measurements and complete response sequences are exported.",
        "session_records": "To reconstruct each original logical session record, replace response_sequence_sha256/response_count/original_relative_path/original_sha256 with complete_response_digests loaded from the named response-sequences file. Its parsed JSON equals the original session record; raw-original hashes refer to original pretty-printed files.",
        "diagnostic": "The first run stopped during capability preflight because the probe used an invalid empty query. No benchmark or answer episode ran. The input was corrected; the entire scheduled evaluation was then run. The failed run is retained.",
    })
    summary = {"schema": "cigar.release-tracking-comparison.v1",
               "performance_sessions": sum(s["sessions"] for s in summaries.values()),
               "complete_response_pairs_verified": sum(s["complete_response_pairs_verified"] for s in summaries.values()),
               "continuation_checks_passed": sum(s["checks_passed"] for s in summaries.values()),
               "answer_replay": read(args.output / "primary/answers/summary.json")["application_kpis"],
               "source_changes": "No CIGAR runtime or SDK changes; new tests, plans and reports only",
               "real_model_hallucination_reduction": None,
               "archive_sha256": sha(args.output / "representative-transcripts.tar.gz")}
    write(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
