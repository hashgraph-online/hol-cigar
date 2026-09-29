"""Freeze and compare three exact local wheels using the established child probes.

Installation is a separate offline phase. Measurements run sequentially, with
OS-denied network access. Nothing here qualifies registry publication.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("baseline", "alpha", "candidate")
PLAN = "docs/proposals/context-release-comparison-0.14.0.md"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    ).encode()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("xb") as stream:
        stream.write(encoded(value))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "missing benchmark module")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def order(cohort):
    offset = cohort % len(LABELS)
    values = LABELS[offset:] + LABELS[:offset]
    return values if cohort % 2 == 0 else values[::-1]


def paired_change(baseline, candidate, limit):
    require(len(baseline) == len(candidate) >= 5, "incomplete paired cohorts")
    require(
        all(math.isfinite(v) and v > 0 for v in baseline + candidate),
        "invalid measurements",
    )
    changes = [
        100 * (right / left - 1)
        for left, right in zip(baseline, candidate, strict=True)
    ]
    rng = random.Random(140027)
    boot = sorted(
        statistics.median(rng.choices(changes, k=len(changes))) for _ in range(4000)
    )
    value = statistics.median(changes)
    return {
        "cohorts": len(changes),
        "paired_percent_changes": changes,
        "median_increase_percent": value,
        "descriptive_95_percent_interval": [boot[99], boot[3899]],
        "maximum_median_increase_percent": limit,
        "guardrail_passed": value <= limit,
    }


def freeze(args):
    output = args.directory.absolute()
    output.mkdir(parents=True, exist_ok=False)
    harness = output / "harness"
    harness.mkdir()
    for name, source in {
        "compare_releases.py": Path(__file__),
        "compare_installed.py": ROOT / "benches/context-012/compare_installed.py",
        "shared_views.py": ROOT / "benchmarks/shared_views.py",
        "import_shared_views.py": ROOT
        / "benches/context-evaluation/import_shared_views.py",
        "evaluation.py": ROOT / "benches/context-evaluation/evaluation.py",
        "plan.md": ROOT / PLAN,
    }.items():
        shutil.copyfile(source, harness / name)
    sys.path.insert(0, str(ROOT / "scripts/release"))
    from context_sdk_cases import build_cases

    answers = module("answer_cases", ROOT / "benches/answer-quality/qualify.py")
    write(output / "compile-cases.json", build_cases(ROOT))
    write(output / "answer-cases.json", answers.cases())
    sys.path.insert(0, str(harness))
    # The frozen importer locates shared_views relative to its repository layout;
    # wheel identity itself only needs that module's pure hash function.
    shared = module("shared_views", harness / "shared_views.py")
    import zipfile
    from email.parser import BytesParser

    artifacts = {}
    for label in LABELS:
        require(
            re.fullmatch(r"[0-9a-f]{40}", getattr(args, label + "_commit") or "")
            is not None,
            "exact source commits are required",
        )
        require(
            re.fullmatch(r"[0-9a-f]{40}", getattr(args, label + "_worker_commit") or "")
            is not None,
            "exact native source commits are required",
        )
        incoming = getattr(args, label + "_wheel").resolve(strict=True)
        destination = output / label
        destination.mkdir()
        wheel = destination / incoming.name
        shutil.copyfile(incoming, wheel)
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            require(
                len(names) == len(set(names)) <= 10_000
                and sum(i.file_size for i in archive.infolist()) <= 1024**3,
                "invalid wheel inventory",
            )
            metadata = [n for n in names if n.endswith(".dist-info/METADATA")]
            require(len(metadata) == 1, "missing package metadata")
            fields = BytesParser().parsebytes(archive.read(metadata[0]))
            require(fields["Name"] == "hol-cigar", "unexpected distribution")
            source_hash = shared.package_source_identity(
                (n.removeprefix("cigar_sdk/"), archive.read(n))
                for n in names
                if n.startswith("cigar_sdk/")
                and not n.endswith("/")
                and "/_native/" not in n
            )
            worker = archive.read("cigar_sdk/_native/darwin-arm64/cigar-context-worker")
        artifacts[label] = {
            "wheel": wheel.relative_to(output).as_posix(),
            "sha256": sha(wheel),
            "version": fields["Version"],
            "sdk_source_sha256": source_hash,
            "worker_sha256": hashlib.sha256(worker).hexdigest(),
            "commit": getattr(args, label + "_commit"),
            "worker_commit": getattr(args, label + "_worker_commit"),
        }
    require(
        len({a["sha256"] for a in artifacts.values()}) == 3,
        "treatments must use distinct archives",
    )
    plan = {
        "schema": "cigar.installed-release-comparison-plan.v1",
        "artifacts": artifacts,
        "python_version": "3.14.7",
        "protobuf": "6.33.5",
        "startup_cohorts": 25,
        "allocation_cohorts": 5,
        "workload_cohorts": 8,
        "agents": [1, 5, 12],
        "documents_per_source": 64,
        "rounds": 50,
        "files": {
            p.relative_to(output).as_posix(): sha(p)
            for p in sorted(output.rglob("*"))
            if p.is_file()
        },
        "network": "macOS sandbox-exec deny network* for every measurement child",
        "candidate_identity_note": "Development artifact is distinguished by commit and archive hash even when its package version matches the retained alpha.",
    }
    write(output / "plan.json", plan)
    print(
        json.dumps({"directory": str(output), "plan_sha256": sha(output / "plan.json")})
    )


def validate(directory):
    plan = json.loads((directory / "plan.json").read_bytes())
    for name, expected in plan["files"].items():
        require(sha(directory / name) == expected, "frozen input changed: " + name)
    require(
        sha(Path(__file__)) == plan["files"]["harness/compare_releases.py"],
        "driver differs from frozen harness",
    )
    return plan


def install(args):
    directory = args.directory.absolute()
    plan = validate(directory)
    logs = directory / "installation"
    logs.mkdir()
    for label, artifact in plan["artifacts"].items():
        environment = directory / label / "environment"
        for name, command in (
            (
                "venv",
                [
                    args.uv,
                    "venv",
                    "--offline",
                    "--python",
                    str(args.python),
                    str(environment),
                ],
            ),
            (
                "install",
                [
                    args.uv,
                    "pip",
                    "install",
                    "--offline",
                    "--python",
                    str(environment / "bin/python"),
                    str(directory / artifact["wheel"]),
                    "protobuf==" + plan["protobuf"],
                ],
            ),
        ):
            result = subprocess.run(command, capture_output=True, timeout=300)
            (logs / f"{label}-{name}.stdout").write_bytes(result.stdout)
            (logs / f"{label}-{name}.stderr").write_bytes(result.stderr)
            require(
                result.returncode == 0,
                f"offline {name} failed for {label}; inspect installation logs",
            )
    validate(directory)


def run(args):
    directory = args.directory.absolute()
    plan = validate(directory)
    require(
        sys.platform == "darwin",
        "this registered study requires the macOS network-deny sandbox",
    )
    output = directory / "observations"
    output.mkdir()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG"}
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"

    def cell(label, name, command):
        python = directory / label / "environment/bin/python"
        result = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1)(allow default)(deny network*)",
                str(python),
                *command,
            ],
            cwd=directory,
            env=environment,
            capture_output=True,
            timeout=600,
        )
        (output / f"{name}-{label}.stdout").write_bytes(result.stdout)
        (output / f"{name}-{label}.stderr").write_bytes(result.stderr)
        require(
            result.returncode == 0,
            f"cell failed: {name}/{label}; retained stdout/stderr",
        )
        return json.loads(result.stdout)

    def probe(label, name, case, memory=False):
        return cell(
            label,
            name,
            [
                str(directory / "harness/compare_installed.py"),
                "--probe",
                case,
                "--output",
                str(directory),
                *(["--memory"] if memory else []),
            ],
        )

    # Verify installed identities before timing, including all imported package
    # source bytes and the actual bundled executable selected by the public API.
    identity_code = """import hashlib,importlib.metadata,json,pathlib,platform,sys
sys.path.insert(0,sys.argv[1])
from shared_views import package_source_identity
import cigar_sdk
from cigar_sdk.local_runtime import bundled_worker
p=pathlib.Path(cigar_sdk.__file__).parent
print(json.dumps({'version':importlib.metadata.version('hol-cigar'),'python_version':platform.python_version(),
'protobuf':importlib.metadata.version('protobuf'),'python_executable_sha256':hashlib.sha256(pathlib.Path(sys.executable).resolve().read_bytes()).hexdigest(),
'sdk_source_sha256':package_source_identity((f.relative_to(p).as_posix(),f.read_bytes()) for f in p.rglob('*') if f.is_file() and '_native' not in f.parts and '__pycache__' not in f.parts),
'worker_sha256':hashlib.sha256(bundled_worker().read_bytes()).hexdigest()}))"""
    identities = {
        label: cell(
            label, "identity", ["-c", identity_code, str(directory / "harness")]
        )
        for label in LABELS
    }
    for label, identity in identities.items():
        for key in ("version", "sdk_source_sha256", "worker_sha256"):
            require(
                identity[key] == plan["artifacts"][label][key],
                "installed artifact mismatch: " + label,
            )
        for key in ("python_version", "protobuf"):
            require(identity[key] == plan[key], "runtime mismatch: " + label)
    require(
        len({i["python_executable_sha256"] for i in identities.values()}) == 1,
        "different interpreter bytes",
    )
    contracts = {label: probe(label, "contracts", "contracts") for label in LABELS}
    for label in LABELS:
        for key in ("compile_results", "answer_results", "golden_id"):
            require(
                contracts[label][key] == contracts["baseline"][key],
                "compatibility mismatch: " + key,
            )
        require(
            contracts[label]["ambiguous_mapping_outcomes"] == ["rejected", "rejected"],
            "ambiguous digest accepted",
        )
        require(
            set(contracts[label]["exports"]) <= set(contracts["candidate"]["exports"]),
            "public export lost",
        )
    print("all installed identities and complete contract outputs agree", flush=True)
    startup = []
    for case in (
        "import",
        "local_api",
        "remote_api",
        "first_graph",
        "graph_open",
        "hash",
    ):
        for memory, count in (
            (False, plan["startup_cohorts"]),
            (True, plan["allocation_cohorts"]),
        ):
            for cohort in range(-2 if not memory else 0, count):
                for label in order(cohort):
                    result = probe(
                        label, f"startup-{case}-{memory}-{cohort}", case, memory
                    )
                    if cohort >= 0:
                        startup.append(
                            {
                                "label": label,
                                "case": case,
                                "memory": memory,
                                "cohort": cohort,
                                **result,
                            }
                        )
        print("completed startup " + case, flush=True)
    write(output / "startup.json", startup)
    rpc = []
    for cohort in range(plan["workload_cohorts"]):
        group = {}
        for label in order(cohort):
            result = probe(label, f"rpc-{cohort}", "rpc")
            group[label] = result
            rpc.append({"label": label, "cohort": cohort, **result})
        require(
            all(
                r["identities"] == group["baseline"]["identities"]
                for r in group.values()
            ),
            "RPC identity mismatch",
        )
        print(f"completed RPC cohort {cohort + 1}", flush=True)
    write(output / "rpc.json", rpc)
    shared_groups = {}
    for agents in plan["agents"]:
        rows = []
        for cohort in range(plan["workload_cohorts"]):
            modes = ("legacy", "shared", "private", "views")
            for mode in modes if cohort % 2 == 0 else modes[::-1]:
                for label in order(cohort):
                    if mode == "views" and label == "baseline":
                        continue
                    result = cell(
                        label,
                        f"shared-{agents}-{cohort}-{mode}",
                        [
                            str(directory / "harness/shared_views.py"),
                            "--mode",
                            mode,
                            "--agents",
                            str(agents),
                            "--documents",
                            str(plan["documents_per_source"]),
                            "--rounds",
                            str(plan["rounds"]),
                        ],
                    )
                    rows.append(
                        {"variant": label + "-" + mode, "cohort": cohort, **result}
                    )
            legacy = [
                r["legacy_output_sha256"]
                for r in rows
                if r["cohort"] == cohort and r["mode"] == "legacy"
            ]
            require(len(set(legacy)) == 1, "shared legacy output changed")
            print(f"completed {agents}-client cohort {cohort + 1}", flush=True)
        shared_groups[agents] = rows
        write(
            output / f"shared-{agents}.json",
            {
                "schema": "cigar.shared-views-comparison.v1",
                "harness_sha256": sha(directory / "harness/shared_views.py"),
                "host": platform.platform(),
                "cohorts": plan["workload_cohorts"],
                "rounds_per_cohort": plan["rounds"],
                "documents_per_source": plan["documents_per_source"],
                "agents": agents,
                "reviewer": "scripted-fixture",
                "agent_execution": "scoped clients in one trusted host; not independent broker processes",
                "legacy_outputs_equal": True,
                "samples": rows,
            },
        )
    comparisons = {}
    for reference in ("baseline", "alpha"):
        for case in {r["case"] for r in startup}:
            selected = [
                [
                    r["ms"]
                    for r in startup
                    if r["label"] == label and r["case"] == case and not r["memory"]
                ]
                for label in (reference, "candidate")
            ]
            comparisons[f"{reference}/startup/{case}"] = paired_change(*selected, 10)
        for metric in ("compile_ms", "update_compile_delta_ms"):
            selected = [
                [statistics.median(r[metric]) for r in rpc if r["label"] == label]
                for label in (reference, "candidate")
            ]
            comparisons[f"{reference}/rpc/{metric}"] = paired_change(*selected, 10)
        for agents, rows in shared_groups.items():
            for mode in ("legacy", "shared", "private", "views"):
                if reference == "baseline" and mode == "views":
                    continue
                selected = [
                    [r for r in rows if r["variant"] == label + "-" + mode]
                    for label in (reference, "candidate")
                ]
                for metric in ("compile", "verify", "review", "replace"):
                    if all(group[0]["raw_timing_ms"][metric] for group in selected):
                        values = [
                            [
                                statistics.median(r["raw_timing_ms"][metric])
                                for r in group
                            ]
                            for group in selected
                        ]
                        comparisons[f"{reference}/{agents}/{mode}/{metric}"] = (
                            paired_change(*values, 10)
                        )
                values = [
                    [r["host_and_worker_rss_sampled_max_bytes"] for r in group]
                    for group in selected
                ]
                comparisons[f"{reference}/{agents}/{mode}/total_rss"] = paired_change(
                    *values, 20
                )
    validate(directory)
    write(
        output / "summary.json",
        {
            "schema": "cigar.installed-release-comparison.v1",
            "plan_sha256": sha(directory / "plan.json"),
            "host": platform.platform(),
            "identities": identities,
            "comparisons": comparisons,
            "failed_guardrails": [
                name
                for name, value in comparisons.items()
                if not value["guardrail_passed"]
            ],
            "compatibility": "passed",
            "provider_calls": 0,
            "limitations": [
                "One host, warm filesystem caches, dependent calls clustered by fresh-process cohort.",
                "Authored answer fixtures are not model truth judgments.",
                "Development candidate, not final seven-platform artifacts.",
            ],
        },
    )
    print(
        "comparison complete; inspect every guardrail in observations/summary.json",
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "install", "run"))
    parser.add_argument("--directory", type=Path, required=True)
    for label in LABELS:
        parser.add_argument("--" + label + "-wheel", type=Path)
        parser.add_argument("--" + label + "-commit")
        parser.add_argument("--" + label + "-worker-commit")
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--python", type=Path)
    arguments = parser.parse_args()
    require(__debug__, "benchmark assertions must remain enabled")
    {"freeze": freeze, "install": install, "run": run}[arguments.command](arguments)
