#!/usr/bin/env python3
"""Run frozen offline answer-adoption and persistent-worker comparisons."""
import argparse
from datetime import UTC, datetime
import errno
import hashlib
import json
from pathlib import Path
import platform
import shutil
import socket
import sys

import answers
import fixtures
import performance
from worker import Worker

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def source_bindings(builds):
    for build in builds.values():
        assert sha(Path(build["binary"])) == build["binary_sha256"]
        for relative, expected in build["source"].items():
            assert sha(Path(build["source_root"]) / relative) == expected, relative


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--section", choices=["all", "answers", "performance"], default="all")
    parser.add_argument("--performance-plan", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    plan = json.loads((HERE / "plan.json").read_text())
    if args.performance_plan:
        if args.section != "performance":
            parser.error("--performance-plan requires --section performance")
        plan["performance"] = json.loads(args.performance_plan.read_text())
        plan["performance_addendum"] = {"path": str(args.performance_plan.resolve()), "sha256": sha(args.performance_plan)}
    build = json.loads(args.build.read_text())
    builds = build["builds"]
    assert builds["baseline"]["version"] == plan["baseline"] and builds["candidate"]["version"] == plan["candidate"]
    assert builds["baseline"]["registry"] == builds["candidate"]["registry"]
    source_bindings(builds)
    write(args.output / "build.json", build)
    inputs = args.output / "inputs"
    inputs.mkdir()
    for path in sorted(HERE.glob("*.py")):
        shutil.copyfile(path, inputs / path.name)
    shutil.copyfile(ROOT / "benches/answer-quality/metrics.py", inputs / "answer_metrics.py")
    write(args.output / "plan.json", plan)
    episodes, reviews = fixtures.episodes(), fixtures.reviews()
    fixtures.validate(episodes, reviews)
    write(inputs / "episodes.json", episodes)
    write(inputs / "reviews.json", reviews)
    write(args.output / "registration.json", {
        "created_at": datetime.now(UTC).isoformat(), "section": args.section,
        "plan_sha256": sha(HERE / "plan.json"),
        "effective_plan_sha256": sha(args.output / "plan.json"),
        "inputs": {p.name: sha(p) for p in sorted(inputs.iterdir())},
        "argv": sys.argv, "python": sys.version, "platform": platform.platform(),
    })
    status = {"status": "running", "section": args.section}
    write(args.output / "status.json", status)
    try:
        with socket.socket() as probe:
            probe.settimeout(.25)
            try:
                probe.connect(("192.0.2.1", 9))
            except OSError as error:
                denied = error.errno
            else:
                denied = None
        assert denied == errno.EPERM, "Run inside an OS network-deny sandbox; evaluation is offline-only"
        write(args.output / "offline-preflight.json", {"external_connect_errno": denied, "external_network_denied": True})
        capability = {}
        for label, item in builds.items():
            worker = Worker(item["binary"], item["version"], args.output / f"capability-{label}.jsonl.gz", domain="tracking/capability")
            try:
                result, _ = worker.ok({"op": "compile", "request": {"query": "capability", "max_tokens": 512}})
                reply, _ = worker.call({"op": "check_answer", "request": {"query": "capability", "max_tokens": 512},
                                        "draft": {"snapshot_id": result["snapshot"]["id"], "claims": [], "abstain": True}, "reviews": [], "policy": {}}, unsupported_probe=True)
                capability[label] = reply
            finally:
                worker.close()
        assert capability["baseline"] == {"id": None, "ok": False, "error": "InvalidInput"}
        assert capability["candidate"]["result"]["decision"] == "abstain"
        write(args.output / "native-capability.json", capability)
        if args.section in ("all", "performance"):
            summary = performance.run(builds, plan["performance"], args.output / "performance")
            print(json.dumps({"performance_complete": True, "response_pairs": summary["complete_response_pairs_verified"]}), flush=True)
        if args.section in ("all", "answers"):
            summary = answers.run(builds, args.output / "answers", episodes, reviews)
            print(json.dumps({"answer_checks": summary["checks"], "application_kpis": summary["application_kpis"]}), flush=True)
        source_bindings(builds)
        status["status"] = "passed"
    except BaseException as error:
        status.update({"status": "failed", "error": f"{type(error).__name__}: {error}"})
        raise
    finally:
        status["completed_at"] = datetime.now(UTC).isoformat()
        write(args.output / "status.json", status)
        write(args.output / "manifest.json", {"schema": "cigar.release-tracking-evidence.v1", "files": {
            str(p.relative_to(args.output)): {"sha256": sha(p), "bytes": p.stat().st_size}
            for p in sorted(args.output.rglob("*")) if p.is_file() and p.name != "manifest.json"}})


if __name__ == "__main__":
    main()
