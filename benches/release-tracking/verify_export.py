#!/usr/bin/env python3
"""Verify exported transcripts, shared response sequences and session records."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def read(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(root, originals=False):
    if (root / "bundle-manifest.json").exists():
        for relative, expected in read(root / "bundle-manifest.json")["files"].items():
            path = root / relative
            assert path.stat().st_size == expected["bytes"] and sha(path) == expected["sha256"], relative
    expected_members = read(root / "transcript-manifest.json")
    members = set()
    with tarfile.open(root / "representative-transcripts.tar.gz", "r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            assert member.isfile() and not path.is_absolute() and ".." not in path.parts and member.name not in members
            expected = expected_members[member.name]
            assert member.size == expected["bytes"]
            with archive.extractfile(member) as source:
                assert hashlib.file_digest(source, "sha256").hexdigest() == expected["sha256"]
            members.add(member.name)
    assert members == set(expected_members)
    summary = read(root / "summary.json")
    assert sha(root / "representative-transcripts.tar.gz") == summary["archive_sha256"]
    sessions, responses, native_checks, original_records = 0, 0, 0, 0
    baseline_version = read(root / "build.json")["builds"]["baseline"]["version"]
    for cohort, info in read(root / "retention.json")["cohorts"].items():
        pairs = {}
        with gzip.open(root / cohort / "performance/session-records.jsonl.gz", "rt") as stream:
            for line in stream:
                row = json.loads(line)
                sequence_hash = row.pop("response_sequence_sha256")
                count = row.pop("response_count")
                relative, original_sha = row.pop("original_relative_path"), row.pop("original_sha256")
                raw = gzip.decompress((root / "response-sequences" / f"{sequence_hash}.json.gz").read_bytes())
                assert hashlib.sha256(raw).hexdigest() == sequence_hash
                sequence = json.loads(raw)
                assert len(sequence) == count
                row["complete_response_digests"] = sequence
                pairs.setdefault((row["mode"], row["pair"]), []).append(sequence_hash)
                if originals:
                    original = Path(info["original_root"]) / relative
                    assert sha(original) == original_sha and read(original) == row
                    original_records += 1
                sessions += 1
                native_checks += len(row["checks"])
                if row["version"] == baseline_version:
                    responses += count
        assert len(pairs) == 16 and all(len(hashes) == 2 and len(set(hashes)) == 1 for hashes in pairs.values())
    assert sessions == summary["performance_sessions"]
    assert responses == summary["complete_response_pairs_verified"]
    assert native_checks == summary["continuation_checks_passed"]
    return {"transcript_members_verified": len(members), "sessions_verified": sessions,
            "original_session_records_reconstructed": original_records, "paired_responses": responses,
            "continuation_checks": native_checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--originals", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.bundle, args.originals)
    if args.output:
        with args.output.open("x") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
