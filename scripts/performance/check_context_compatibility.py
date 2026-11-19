#!/usr/bin/env python3
"""Compare complete outputs and exchange snapshots/deltas between two local versions.

Uses the unchanged release qualification corpus. This is local compatibility
evidence, not release qualification, and never downloads or publishes artifacts.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def consume(args):
    sys.path.insert(0, str(args.sdk_root.resolve(strict=True)))
    import cigar_sdk
    from cigar_sdk import LocalContextError, LocalContextGraph

    if args.exchange:
        rows = json.loads(args.exchange.read_bytes())["results"]
        verified = 0
        with LocalContextGraph("cross-version-verify", worker_path=args.worker) as graph:
            for row in rows:
                if "error" in row:
                    continue
                assert graph.verify(row["result"]["snapshot"]) == row["result"]
                assert graph.verify(row["target"]["snapshot"]) == row["target"]
                assert graph.delta(row["result"]["snapshot"], row["target"]["snapshot"]) == row["delta"]
                assert graph.apply_delta(row["result"]["snapshot"], row["delta"]) == row["target"]
                verified += 1
        assert graph.cleanup_complete
        return {"verified_snapshot_delta_pairs": verified}

    cases = json.loads(args.cases.read_bytes())
    results = []
    capabilities = None
    for case in cases:
        with LocalContextGraph(case["domain"], worker_path=args.worker) as graph:
            capabilities = graph.capabilities()
            for document in case["documents"]:
                graph.upsert(document)
            for start, end, kind in case["edges"]:
                graph.link(start, end, kind)
            try:
                result = graph.compile(case["request"])
            except LocalContextError as error:
                results.append({"error": error.code})
            else:
                assert graph.verify(result["snapshot"]) == result
                # Retain a real changed snapshot and its exact-base transport.
                document = dict(case["documents"][-1])
                document["text"] += "\nCompatibility revision: preserve UTF8 café 中文 🙂."
                graph.upsert(document)
                # Allow room for the extra text; the original request's tight
                # budget and expected refusals were already checked above.
                target_request = dict(case["request"], max_tokens=4096)
                target = graph.compile(target_request)
                delta = graph.delta(result["snapshot"], target["snapshot"])
                assert graph.apply_delta(result["snapshot"], delta) == target
                results.append({"result": result, "target": target, "delta": delta})
        assert graph.cleanup_complete
    return {"exports": sorted(cigar_sdk.__all__), "capabilities": capabilities, "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-sdk", type=Path)
    parser.add_argument("--baseline-worker", type=Path)
    parser.add_argument("--candidate-sdk", type=Path)
    parser.add_argument("--candidate-worker", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--consumer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--sdk-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--cases", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--exchange", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not __debug__:
        parser.error("compatibility verification requires assertions enabled")
    if args.consumer:
        print(json.dumps(consume(args), ensure_ascii=False))
        return
    if any(value is None for value in [args.baseline_sdk, args.baseline_worker,
                                       args.candidate_sdk, args.candidate_worker, args.output]):
        parser.error("both SDKs/workers and a new output directory are required")
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / "scripts/release"))
    from context_sdk_cases import build_cases
    cases = build_cases(ROOT)
    cases_path = args.output / "cases.json"
    cases_path.write_text(json.dumps(cases, ensure_ascii=False) + "\n")

    def invoke(name, sdk, worker, exchange=None):
        command = [sys.executable, str(Path(__file__).resolve()), "--consumer",
                   "--sdk-root", str(sdk.resolve(strict=True)),
                   "--worker", str(worker.resolve(strict=True)), "--cases", str(cases_path.resolve())]
        if exchange:
            command += ["--exchange", str(exchange.resolve())]
        with (args.output / (name + ".json")).open("xb") as stdout, \
                (args.output / (name + ".stderr")).open("xb") as stderr:
            subprocess.run(command, stdout=stdout, stderr=stderr, check=True, timeout=300)
        return json.loads((args.output / (name + ".json")).read_bytes())

    baseline = invoke("baseline", args.baseline_sdk, args.baseline_worker)
    candidate = invoke("candidate", args.candidate_sdk, args.candidate_worker)
    assert baseline["exports"] == candidate["exports"], "public exports changed"
    assert baseline["results"] == candidate["results"], "complete response/snapshot/delta mismatch"
    old_in_new = invoke("baseline-in-candidate", args.candidate_sdk, args.candidate_worker,
                        args.output / "baseline.json")
    new_in_old = invoke("candidate-in-baseline", args.baseline_sdk, args.baseline_worker,
                        args.output / "candidate.json")
    # Version negotiation changes; capability support must not shrink.
    old_features = baseline["capabilities"]["features"]
    new_features = candidate["capabilities"]["features"]
    assert old_features == new_features, "capability coverage changed"
    report = {"schema": "cigar.cross-version-compatibility.v1", "status": "passed",
              "cases": len(cases), "successful_cases": sum("result" in row for row in baseline["results"]),
              "expected_errors": sum("error" in row for row in baseline["results"]),
              "baseline_version": baseline["capabilities"]["core_version"],
              "candidate_version": candidate["capabilities"]["core_version"],
              "exports": len(baseline["exports"]), "old_in_new": old_in_new, "new_in_old": new_in_old,
              "worker_sha256": {"baseline": hashlib.sha256(args.baseline_worker.read_bytes()).hexdigest(),
                                 "candidate": hashlib.sha256(args.candidate_worker.read_bytes()).hexdigest()},
              "scope": "Exact release corpus outputs, changed snapshots/deltas and bidirectional verification; local only"}
    with (args.output / "report.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
