"""Gate statement and branch coverage separately; never substitute combined coverage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_lib import reject_evidence_directory


def validate(document: dict) -> dict:
    limits = {
        "total": (90, 85),
        "digest.py": (98, 95),
        "context.py": (95, 90),
        "local_runtime.py": (95, 90),
        "transport.py": (95, 90),
    }
    summaries = {"total": document["totals"]}
    for name, data in document["files"].items():
        if Path(name).name in limits:
            summaries[Path(name).name] = data["summary"]
    if summaries.keys() != limits.keys():
        raise ValueError("coverage evidence is missing a required runtime module")
    result = {}
    for name, (statements, branches) in limits.items():
        row = summaries[name]
        if not row["num_statements"] or not row["num_branches"]:
            raise ValueError("coverage evidence has an empty denominator")
        observed = {
            "statements": 100 * row["covered_lines"] / row["num_statements"],
            "branches": 100 * row["covered_branches"] / row["num_branches"],
        }
        if observed["statements"] < statements or observed["branches"] < branches:
            raise ValueError(
                f"{name} coverage is below {statements}% statements / {branches}% branches: {observed}"
            )
        result[name] = observed
    return {
        "schema": "cigar.python-coverage-gate.v1",
        "status": "passed",
        "coverage": result,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to stdout checks"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "coverage report check")
    print(json.dumps(validate(json.loads(args.report.read_text())), sort_keys=True))
