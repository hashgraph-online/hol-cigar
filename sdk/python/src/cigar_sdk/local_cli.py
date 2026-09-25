"""Local diagnostics and a complete workflow; no HOL service or model provider."""

from __future__ import annotations

import argparse
import json

from cigar_sdk.context import LocalContextError, LocalContextGraph, get_local_context_capabilities
from cigar_sdk.examples.local_workflow import run_local_workflow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cigar-context", description=__doc__)
    parser.add_argument("command", choices=["doctor", "demo"])
    parser.add_argument("--json", action="store_true", help="emit a machine-readable result")
    parser.add_argument("--worker", help="explicit absolute trusted matching worker executable")
    args = parser.parse_args(argv)
    capabilities = get_local_context_capabilities(worker_path=args.worker)
    try:
        if args.command == "demo":
            print(json.dumps(run_local_workflow(worker_path=args.worker), indent=None if args.json else 2))
            return 0
        with LocalContextGraph("cigar-doctor", worker_path=args.worker, timeout=5.0) as graph:
            graph.upsert({"id": "doctor", "source": "cigar:doctor", "text": "Local context compilation works."})
            compiled = graph.compile({"required": ["doctor"], "allowed": ["doctor"], "max_tokens": 256})
            if graph.verify(compiled["snapshot"]) != compiled or compiled["snapshot"]["stats"]["rendered_tokens"] > 256:
                raise LocalContextError("Integrity")
            tokens = compiled["snapshot"]["stats"]["rendered_tokens"]
        report = {
            "schema": "cigar.local-diagnostics.v1",
            "status": "ready",
            "capabilities": capabilities,
            "compile_verified": True,
            "rendered_tokens": tokens,
        }
        print(
            json.dumps(report)
            if args.json
            else f"CIGAR {capabilities['package_version']}: ready on {capabilities['platform']} "
            f"({capabilities['runtime']}).\n"
            f"Local compilation and snapshot verification passed ({tokens} tokens).\n"
            "No HOL service, account or API key is required."
        )
        return 0
    except LocalContextError as error:
        failure = {
            "schema": "cigar.local-diagnostics.v1",
            "status": "error",
            "capabilities": capabilities,
            "compile_verified": False,
            "error_code": error.code,
            "guidance": str(error),
        }
        print(
            json.dumps(failure)
            if args.json
            else f"CIGAR {capabilities['package_version']}: {error.code} on {capabilities['platform']}.\n{error}"
        )
        return 1
    except Exception:
        failure = {
            "schema": "cigar.local-diagnostics.v1",
            "status": "error",
            "capabilities": capabilities,
            "compile_verified": False,
            "error_code": "Internal",
            "guidance": "The local diagnostic failed unexpectedly.",
        }
        print(json.dumps(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
