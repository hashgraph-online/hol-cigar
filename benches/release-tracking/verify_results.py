#!/usr/bin/env python3
"""Independently audit saved source bodies, scope, gold labels and evidence hashes."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

import answers
import fixtures
from worker import canonical


def audit_trace(records):
    documents = {}
    counts = {"commands": 0, "successful_compiles": 0, "required_document_body_checks": 0}
    reply_digests = set()
    for record in records:
        counts["commands"] += 1
        command, reply = record["request"]["command"], record["reply"]
        reply_digests.add(hashlib.sha256(canonical(reply)).hexdigest())
        if not reply["ok"]:
            continue
        operation = command["op"]
        if operation == "upsert":
            documents[command["document"]["id"]] = command["document"]
        elif operation == "replace_source":
            documents = {key: value for key, value in documents.items() if value["source"] != command["source"]}
            documents.update({d["id"]: d for d in command["documents"]})
        elif operation == "remove":
            documents.pop(command["node_id"], None)
        elif operation == "compile":
            counts["successful_compiles"] += 1
            request, snapshot = command["request"], reply["result"]["snapshot"]
            selected = {citation["node_id"] for block in snapshot["blocks"] for citation in block["citations"]}
            assert set(request.get("required", [])) <= selected
            if "allowed" in request:
                assert selected <= set(request["allowed"])
            assert snapshot["stats"]["rendered_tokens"] <= request["max_tokens"]
            for identity in request.get("required", []):
                assert identity in documents, "withdrawn required source was served"
                supporting = [block for block in snapshot["blocks"] if any(c["node_id"] == identity for c in block["citations"])]
                # These full-document fixtures have one complete body per block;
                # substring presence would incorrectly accept "3" replaced by "30".
                assert any(documents[identity]["text"] == block["text"] for block in supporting), "citation present but required source body missing or changed"
                counts["required_document_body_checks"] += 1
    return counts, reply_digests


def audit(root):
    manifest = json.loads((root / "manifest.json").read_text())
    for relative, expected in manifest["files"].items():
        path = root / relative
        assert path.stat().st_size == expected["bytes"], relative
        with path.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected["sha256"], relative
    assert json.loads((root / "status.json").read_text())["status"] == "passed"
    totals = {"files_verified": len(manifest["files"]), "traces": 0, "commands": 0, "successful_compiles": 0,
              "required_document_body_checks": 0, "independent_answer_rows_verified": 0}
    answer_replies = {}
    for trace in sorted(root.rglob("*.jsonl.gz")):
        with gzip.open(trace, "rt") as stream:
            counts, digests = audit_trace(json.loads(line) for line in stream)
        totals["traces"] += 1
        for key, value in counts.items():
            totals[key] += value
        if trace.parent.name == "answers":
            answer_replies[trace.name] = digests
    if (root / "answers/episodes.jsonl").exists():
        episodes = {e["id"]: e for e in json.loads((root / "inputs/episodes.json").read_text())}
        for line in (root / "answers/episodes.jsonl").read_text().splitlines():
            row = json.loads(line)
            episode = episodes[row["episode_id"]]
            for index, history in enumerate(row["history"]):
                expected = [{"text": fixtures.text(c["fact"], c["value"]), "citations": c["citations"], "confidence_bps": c["confidence_bps"]} for c in episode["attempts"][index]["claims"]]
                assert history["draft"]["claims"] == expected
                replies = answer_replies[f"{episode['id']}-{row['treatment']}.jsonl.gz"]
                assert hashlib.sha256(canonical(history["response"])).hexdigest() in replies
                if row["treatment"] == "v11_reviewed_host":
                    reply = history["response"]
                    actual = reply["result"]["decision"] if reply["ok"] else reply["error"]
                else:
                    actual = answers.citation_host(history["response"], history["draft"])
                assert actual == history["decision"]
            last = row["history"][-1]
            displayed = episode["attempts"][len(row["history"]) - 1]["claims"] if last["decision"] == "release" else []
            assert row["claims"] == fixtures.annotations(episode, displayed)
            assert row["abstained"] == (not displayed)
            totals["independent_answer_rows_verified"] += 1
    return totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="+")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {str(path): audit(path) for path in args.results}
    if args.output:
        with args.output.open("x") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
