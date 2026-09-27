"""Verify frozen source-load evidence and summarize whole process cohorts."""

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
import statistics

from broker_load import no_credentials, quantile, verify_load_cell
from broker_storage import encoded, file_hash, paired


def read(path, maximum=64 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("invalid evidence file")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate evidence member")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite evidence value")

    return json.loads(
        path.read_bytes(), object_pairs_hook=pairs, parse_constant=invalid
    )


def relative(root, name):
    path = Path(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ValueError("invalid evidence member path")
    target = root / path
    if any(
        (root / Path(*path.parts[:index])).is_symlink()
        for index in range(1, len(path.parts) + 1)
    ):
        raise ValueError("evidence symlink is not a regular retained input")
    return target


def distribution(values):
    return {
        "cohorts": len(values),
        "median": statistics.median(values),
        "p95": quantile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def measures(row):
    agents = row["result"]["agents"]
    return {
        "compile_median_ms": statistics.median(
            agent["compile_ms"]["p50"] for agent in agents
        ),
        "total_cycles_per_second": sum(agent["cycles_per_second"] for agent in agents),
        "sampled_total_rss_bytes": max(
            sample["total"] for sample in row["rss_samples"]
        ),
        "sampled_worker_rss_bytes": max(
            sample["worker"] for sample in row["rss_samples"]
        ),
    }


def summarize(rows, plan):
    dimensions = plan["cells"]
    combinations = list(
        itertools.product(
            dimensions["agents"],
            dimensions["runtimes"],
            dimensions["storage"],
            dimensions["parallelism"],
        )
    )
    expected = {
        (cohort, *combination)
        for cohort in range(plan["cohorts"])
        for combination in combinations
    }
    keyed = {}
    for row in rows:
        key = (
            row["cohort"],
            row["agents"],
            row["runtime"],
            row["storage"],
            row["parallelism"],
        )
        if key not in expected or key in keyed:
            raise ValueError("missing, duplicate or foreign process cohort")
        keyed[key] = row
    if set(keyed) != expected:
        raise ValueError("missing, duplicate or foreign process cohort")
    groups = {}
    renderings = {}
    for agents, runtime, storage, parallelism in combinations:
        name = f"{agents}/{runtime}/{storage}/{parallelism}"
        selected = [
            keyed[(cohort, agents, runtime, storage, parallelism)]
            for cohort in range(plan["cohorts"])
        ]
        failed = [
            row["cohort"]
            for row in selected
            if row.get("result", {}).get("status") != "passed"
        ]
        if failed:
            groups[name] = {
                "status": "incomplete",
                "failed_or_missing_observation_cohorts": failed,
                "metrics": None,
            }
            continue
        for row in selected:
            digest = tuple(
                observation["samples"][0]["rendered_sha256"]
                for observation in row["observations"]
            )
            # Runtime, persistence and scheduling must not change the fixture's rendered context.
            if agents in renderings and renderings[agents] != digest:
                raise ValueError(
                    "same fixture rendered different context across load treatments"
                )
            renderings[agents] = digest
        values = [measures(row) for row in selected]
        gates = [agent for row in selected for agent in row["result"]["agents"]]
        groups[name] = {
            "status": "passed",
            "metrics": {
                key: distribution([value[key] for value in values]) for key in values[0]
            },
            "attempted": sum(agent["attempted"] for agent in gates),
            "completed": sum(agent["completed"] for agent in gates),
            "worst_agent_p95_ms": max(agent["compile_ms"]["p95"] for agent in gates),
            "worst_agent_p99_ms": max(agent["compile_ms"]["p99"] for agent in gates),
            "min_agent_cycles_per_second": min(
                agent["cycles_per_second"] for agent in gates
            ),
            "min_same_runtime_completion_ratio": min(
                value["min_max_ratio"]
                for row in selected
                for value in row["result"]["fairness"].values()
            ),
            "min_same_runtime_jain": min(
                value["jain"]
                for row in selected
                for value in row["result"]["fairness"].values()
            ),
        }
    tradeoffs = {}
    if set(dimensions["parallelism"]) == {1, 4}:
        for agents, runtime, storage in itertools.product(
            dimensions["agents"], dimensions["runtimes"], dimensions["storage"]
        ):
            name = f"{agents}/{runtime}/{storage}"
            members = [groups[f"{name}/{parallelism}"] for parallelism in (1, 4)]
            if any(group["status"] != "passed" for group in members):
                tradeoffs[name] = {"status": "incomplete", "paired": None}
                continue
            values = [
                (
                    measures(keyed[(cohort, agents, runtime, storage, 1)]),
                    measures(keyed[(cohort, agents, runtime, storage, 4)]),
                )
                for cohort in range(plan["cohorts"])
            ]
            tradeoffs[name] = {
                "status": "comparable",
                "paired": {
                    metric: paired(
                        [(one[metric], four[metric]) for one, four in values]
                    )
                    for metric in values[0][0]
                },
            }
    return {
        "groups": groups,
        "one_to_four_inflight_tradeoffs": tradeoffs,
        "interpretation": "Same candidate with increased concurrency; not a version nonregression or efficacy comparison. "
        "Each interval resamples whole paired fresh process cohorts; fewer than eight gives no interval. "
        "RPC tails and fairness remain descriptive per-agent gates. No source writes occur in load windows.",
    }


def verify(directory):
    plan = read(directory / "plan.json", 4 * 1024 * 1024)
    result = read(directory / "result.json", 4 * 1024 * 1024)
    if (
        plan.get("schema") != "cigar.broker-load-bound-plan.v1"
        or plan.get("study") != "load"
    ):
        raise ValueError("only registered load observations are supported")
    if result.get("schema") != "cigar.broker-load.v1" or result.get(
        "plan_sha256"
    ) != file_hash(directory / "plan.json"):
        raise ValueError("unbound load result")
    manifests = (
        (directory / "python/cigar_sdk", plan["python_files"]),
        (directory / "typescript", plan["node_files"]),
        (directory / "harness", plan["harnesses"]),
    )
    for root, members in manifests:
        for name, expected in members.items():
            if file_hash(relative(root, name)) != expected:
                raise ValueError("changed retained SDK/harness input")
    if file_hash(directory / "worker") != plan["worker_sha256"]:
        raise ValueError("changed retained worker")
    dimensions = plan["cells"]
    combinations = list(
        itertools.product(
            dimensions["agents"],
            dimensions["runtimes"],
            dimensions["storage"],
            dimensions["parallelism"],
        )
    )
    expected = [
        (cohort, *combination)
        for cohort in range(plan["cohorts"])
        for combination in (combinations if cohort % 2 == 0 else reversed(combinations))
    ]
    if len(result["cells"]) != len(expected):
        raise ValueError("missing or duplicated cell reference")
    rows = []
    for reference, (cohort, agents, runtime, storage, parallelism) in zip(
        result["cells"], expected, strict=True
    ):
        name = f"cell-{cohort}-{agents}-{runtime}-{storage}-{parallelism}.json"
        if (
            reference["file"] != name
            or file_hash(relative(directory, name)) != reference["sha256"]
        ):
            raise ValueError("changed, missing or duplicated cell")
        row = read(directory / name)
        no_credentials(row)
        status = row.get("result", {}).get("status", "incomplete")
        if status != reference["status"]:
            raise ValueError("cell status mismatch")
        if row.get("schema") == "cigar.broker-load-cell.v1":
            verify_load_cell(
                row,
                plan["configuration"],
                agents,
                runtime,
                storage,
                parallelism,
                plan["duration_ms"],
            )
        elif status != "incomplete":
            raise ValueError("invalid successful cell")
        rows.append(
            {
                **row,
                "cohort": cohort,
                "agents": agents,
                "runtime": runtime,
                "storage": storage,
                "parallelism": parallelism,
            }
        )
    expected_status = (
        "passed"
        if all(reference["status"] == "passed" for reference in result["cells"])
        else "incomplete"
    )
    if result.get("status") != expected_status:
        raise ValueError("aggregate status mismatch")
    return {
        "schema": "cigar.broker-load-report.v1",
        "plan_sha256": file_hash(directory / "plan.json"),
        "raw_result_sha256": file_hash(directory / "result.json"),
        "reporter_sha256": file_hash(Path(__file__)),
        "status": expected_status,
        "summary": summarize(rows, plan),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.directory)
    with args.output.open("xb") as handle:
        handle.write(encoded(result))
    print(
        json.dumps(
            {"status": result["status"], "groups": len(result["summary"]["groups"])},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
