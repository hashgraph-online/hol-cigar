#!/usr/bin/env python3
"""Install exact distribution archives, then qualify them under an OS network policy.

Preparation may download pinned dependencies. The offline phase executes the Rust
oracle, installed wheel/sdist/npm consumers, diagnostics and complete examples.
No phase calls a model provider or uses an LLM to judge the fixture answers.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys

from build_context_worker import host_matches
import context_distribution as distribution
import context_platforms
import context_sdk_inputs
from context_sdk_cases import build_cases
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
)

ROOT = distribution.ROOT
require = distribution.require
RUNTIMES = {
    "minimum": {"node": "24.10.0", "python": "3.14.0"},
    "current": {"node": "24.19.0", "python": "3.14.7"},
}
FIREWALL_GROUP = "CIGAR context distribution qualification"


def executable(venv: Path, name: str) -> Path:
    return (
        venv
        / ("Scripts" if os.name == "nt" else "bin")
        / (name + ".exe" if os.name == "nt" else name)
    )


def runtime_versions() -> dict:
    return {
        "python": platform.python_version(),
        "node": subprocess.check_output(["node", "--version"], text=True, timeout=30)
        .strip()
        .removeprefix("v"),
    }


def environment(output: Path) -> dict:
    # Tests cannot accidentally resolve the source SDK through a caller override.
    result = os.environ.copy()
    result.pop("CIGAR_TEST_WORKER", None)
    result.pop("CIGAR_TEST_STALLED_WORKER", None)
    result["PYTHONPATH"] = ""
    result["npm_config_cache"] = str(output / "npm-cache")
    return result


def prepare(args) -> None:
    require(
        host_matches(args.platform),
        "installed tests must execute on their declared OS/architecture/libc",
    )
    candidate = args.candidate.absolute()
    report = distribution.verify_candidate(candidate, release=not args.allow_diagnostic)
    require(
        args.platform in report["platforms"], "candidate does not include this platform"
    )
    versions = runtime_versions()
    require(
        versions == RUNTIMES[args.runtime],
        "test runtimes differ from the declared pinned pair",
    )
    context_sdk_inputs.require_unchanged(
        ROOT, report["source_binding"], allow_dirty=report["diagnostic"]
    )
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    runner = distribution.Runner(output, environment(output))
    metadata = context_platforms.platforms()[args.platform]
    worker = (
        candidate
        / "workers"
        / args.platform
        / "native"
        / args.platform
        / metadata["executable"]
    )
    fixture_name = "stalled-worker.exe" if os.name == "nt" else "stalled-worker"
    fixture = (
        args.stalled_worker
        or candidate / "workers" / args.platform / "oracle" / fixture_name
    )
    require(
        fixture.is_file(),
        "transport timeout fixture is required; no skipped timeout tests",
    )
    fixture.chmod(0o755)
    runner.environment["CIGAR_TEST_STALLED_WORKER"] = str(fixture)
    binaries = {
        str(Path(sys.executable).resolve()),
        str(Path(shutil.which("node")).resolve()),
        str(worker),
    }
    archives = candidate / "artifacts"
    for kind, archive in (
        (
            "wheel",
            archives
            / f"hol_cigar-{distribution.VERSION}-py3-none-{metadata['wheel_tag']}.whl",
        ),
        ("sdist", archives / f"hol_cigar-{distribution.VERSION}.tar.gz"),
    ):
        venv = output / (kind + "-venv")
        runner.run(kind + "-venv", [args.uv, "venv", "--python", sys.executable, venv])
        python = executable(venv, "python")
        runner.run(
            kind + "-install",
            [args.uv, "pip", "install", "--python", python, archive, "pytest==9.0.3"],
        )
        if kind == "sdist":
            runner.environment["CIGAR_TEST_WORKER"] = str(worker)
        else:
            runner.environment.pop("CIGAR_TEST_WORKER", None)
        result = runner.run(
            kind + "-tests",
            [python, "-m", "pytest", ROOT / "sdk/python/tests", "-q"],
            cwd=output,
        ).decode()
        require(
            "passed" in result and "skipped" not in result,
            "Python installed tests were skipped",
        )
        runner.run(
            kind + "-legacy-entrypoint",
            [executable(venv, "cigar-qualify-bundle")],
            cwd=output,
        )
        binaries.update((str(python), str(executable(venv, "cigar-context"))))
        for item in venv.rglob(metadata["executable"]):
            binaries.add(str(item))
    runner.environment.pop("CIGAR_TEST_WORKER", None)
    npm = output / "npm-consumer"
    npm.mkdir()
    (npm / "package.json").write_text('{"private":true,"type":"module"}\n')
    command = distribution.npm_command(args.npm)
    runner.run(
        "npm-install",
        [
            *command,
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            archives / f"hol-org-cigar-{distribution.VERSION}.tgz",
        ],
        cwd=npm,
    )
    shutil.copyfile(
        ROOT / "scripts/release/context-sdk-consumer.mjs", npm / "consumer.mjs"
    )
    installed = npm / "node_modules/@hol-org/cigar"
    require(
        not (installed / "dist/tests").exists(),
        "npm consumer unexpectedly contains source tests",
    )
    binaries.add(str(installed / "native" / args.platform / metadata["executable"]))
    test_copy = output / "npm-installed-tests"
    shutil.copytree(installed, test_copy)
    shutil.copytree(
        npm / "node_modules/@bufbuild", test_copy / "node_modules/@bufbuild"
    )
    shutil.copytree(candidate / "typescript-tests", test_copy / "dist/tests")
    # The remote SDK fixture files are test-only inputs, not runtime services.
    shutil.copytree(ROOT / "sdk/fixtures", output / "fixtures")
    for name in ("workflow-context-session.v1.json", "capabilities-v1.json"):
        shutil.copyfile(ROOT / "sdk" / name, output / name)
    result = runner.run(
        "npm-installed-tests",
        ["node", "--test", *sorted((test_copy / "dist/tests").glob("*.test.js"))],
        cwd=output,
    ).decode()
    require(
        "# fail 0" in result and "# skipped 0" in result,
        "TypeScript installed tests failed or were skipped",
    )
    cases = build_cases(ROOT)
    (output / "cases.json").write_bytes(canonical_json_bytes(cases))
    # The native Rust oracle must also execute within the offline policy.
    oracle = (
        candidate
        / "workers"
        / args.platform
        / "oracle"
        / ("cigar-context.exe" if os.name == "nt" else "cigar-context")
    )
    oracle.chmod(0o755)
    binaries.add(str(oracle))
    (output / "programs.json").write_bytes(canonical_json_bytes(sorted(binaries)))
    document = {
        "schema": "cigar.context-distribution-install.v1",
        "status": "installed-tests-passed",
        "candidate": str(candidate),
        "candidate_sha256": distribution.file_record(candidate / "candidate.json")[
            "sha256"
        ],
        "candidate_artifacts": report["artifacts"],
        "source_binding": report["source_binding"],
        "platform": args.platform,
        "runtime": args.runtime,
        "versions": versions,
        "diagnostic": report["diagnostic"],
        "npm_command": command,
        "checks": runner.checks,
        "cases": distribution.file_record(output / "cases.json"),
        "programs": distribution.file_record(output / "programs.json"),
    }
    (output / "prepare.json").write_bytes(canonical_json_bytes(document))
    print(
        json.dumps(
            {
                "status": document["status"],
                "platform": args.platform,
                "versions": versions,
            }
        )
    )


def network_policy(output: Path, platform_id: str) -> dict:
    policy = {"provider_calls": 0}
    if platform_id.startswith("darwin-"):
        policy["kind"] = "macos-sandbox-deny-network"
        addresses = ["1.1.1.1", "127.0.0.1"]
        errors = {errno.EPERM, errno.EACCES}
    elif platform_id.startswith("linux-"):
        require(
            {path.name for path in Path("/sys/class/net").iterdir()} == {"lo"},
            "Linux offline phase requires an isolated network namespace with only loopback",
        )
        policy["kind"] = "linux-network-namespace-none"
        addresses = ["1.1.1.1"]
        errors = {errno.ENETUNREACH, errno.EACCES, errno.EPERM}
    else:
        policy["kind"] = "windows-outbound-program-firewall"
        script = (
            "$ErrorActionPreference='Stop'; "
            "$profiles=@(Get-NetFirewallProfile | Select-Object Name,Enabled); "
            f"$rules=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' | "
            "ForEach-Object { $rule=$_; $filter=$rule | Get-NetFirewallApplicationFilter; "
            "[pscustomobject]@{Program=$filter.Program; Enabled=[string]$rule.Enabled; "
            "Action=[string]$rule.Action; Direction=[string]$rule.Direction}}); "
            "@{profiles=$profiles;rules=$rules} | ConvertTo-Json -Depth 5 -Compress"
        )
        state = json.loads(
            subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=30,
            )
        )
        require(
            len(state["profiles"]) == 3
            and all(row["Enabled"] for row in state["profiles"]),
            "Windows firewall profiles must be enabled",
        )
        blocked = {
            os.path.normcase(row["Program"])
            for row in state["rules"]
            if row["Enabled"] == "True"
            and row["Action"] == "Block"
            and row["Direction"] == "Outbound"
        }
        required = {
            os.path.normcase(name) for name in load_json(output / "programs.json")
        }
        require(
            required <= blocked,
            "Windows outbound deny rules do not cover every tested executable",
        )
        policy["verified_rules"] = state
        policy["limitation"] = (
            "Program firewall denies external outbound traffic; Windows loopback filtering is not claimed."
        )
        addresses = ["1.1.1.1"]
        errors = {errno.EACCES, errno.EPERM, errno.ETIMEDOUT, 10013, 10060}
    probes = []
    for address in addresses:
        try:
            with socket.create_connection((address, 443), timeout=2):
                raise ReleaseError("offline phase unexpectedly has network access")
        except OSError as error:
            require(
                isinstance(error, TimeoutError)
                and platform_id == "win32-x64"
                or error.errno in errors,
                "network probe did not demonstrate the required OS denial",
            )
            probes.append({"address": address, "errno": error.errno, "denied": True})
    return policy | {"probes": probes}


def offline(args) -> None:
    output = args.output.absolute()
    prepared = load_json(output / "prepare.json")
    require(
        prepared["status"] == "installed-tests-passed",
        "installed preparation did not pass",
    )
    require(
        prepared["versions"] == runtime_versions(), "runtime changed after installation"
    )
    require(
        host_matches(prepared["platform"]),
        "offline phase moved to a different platform",
    )
    candidate = Path(prepared["candidate"])
    require(
        distribution.file_record(candidate / "candidate.json")["sha256"]
        == prepared["candidate_sha256"],
        "candidate changed after installation",
    )
    require(
        distribution.file_record(output / "cases.json") == prepared["cases"],
        "comparison cases changed",
    )
    require(
        distribution.file_record(output / "programs.json") == prepared["programs"],
        "network program inventory changed",
    )
    directory = output / "offline"
    directory.mkdir()
    policy = network_policy(output, prepared["platform"])
    (directory / "network-policy.json").write_bytes(canonical_json_bytes(policy))
    runner = distribution.Runner(directory, environment(output))
    key = prepared["platform"]
    metadata = context_platforms.platforms()[key]
    worker = candidate / "workers" / key / "native" / key / metadata["executable"]
    oracle = (
        candidate
        / "workers"
        / key
        / "oracle"
        / ("cigar-context.exe" if os.name == "nt" else "cigar-context")
    )
    cases = load_json(output / "cases.json")
    expected = []
    for case in cases:
        result = subprocess.run(
            [str(oracle)],
            input=canonical_json_bytes(case),
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            error = result.stderr.decode().strip().removeprefix("Error: ")
            require(
                error
                in {
                    "RequiredUnavailable",
                    "BudgetUnsatisfiable",
                    "LimitExceeded",
                    "InvalidInput",
                },
                "unexpected Rust oracle failure",
            )
            expected.append({"error": error})
        else:
            expected.append({"snapshot": json.loads(result.stdout)})
    (directory / "rust-oracle.json").write_bytes(canonical_json_bytes(expected))
    results, demos = {}, {}
    for kind in ("wheel", "sdist", "npm"):
        if kind == "npm":
            cwd = output / "npm-consumer"
            command = ["node", "consumer.mjs", output / "cases.json"]
            cli = [*prepared["npm_command"], "exec", "--offline", "--", "cigar-context"]
            explicit = []
        else:
            cwd = output
            venv = output / (kind + "-venv")
            command = [
                executable(venv, "python"),
                ROOT / "scripts/release/context_sdk_consumer.py",
                output / "cases.json",
            ]
            explicit = ["--worker", str(worker)] if kind == "sdist" else []
            if explicit:
                command.append(worker)
            cli = [executable(venv, "cigar-context")]
        response = json.loads(runner.run(kind + "-offline-oracle", command, cwd=cwd))
        if kind != "npm":
            require(
                Path(response["module"]).resolve().is_relative_to(venv.resolve()),
                "consumer imported a source-tree SDK",
            )
        results[kind] = response
        require(
            len(response["results"]) == len(expected), "consumer case count differs"
        )
        for actual, reference in zip(response["results"], expected, strict=True):
            require(
                ({"snapshot": actual["snapshot"]} if "snapshot" in actual else actual)
                == reference,
                "installed consumer differs from Rust oracle",
            )
        doctor = json.loads(
            runner.run(kind + "-doctor", [*cli, "doctor", "--json", *explicit], cwd=cwd)
        )
        require(
            doctor["status"] == "ready"
            and doctor["compile_verified"] is True
            and doctor["capabilities"]["requires_hol_services"] is False,
            "installed diagnostic did not perform a standalone compile",
        )
        demos[kind] = json.loads(
            runner.run(kind + "-demo", [*cli, "demo", "--json", *explicit], cwd=cwd)
        )
        require(
            demos[kind]["status"] == "passed"
            and demos[kind]["reviewer"] == "scripted-fixture",
            "complete installed workflow failed",
        )
        missing = json.loads(
            runner.run(
                kind + "-missing-worker",
                [
                    *cli,
                    "doctor",
                    "--json",
                    "--worker",
                    str(output / "PRIVATE_MISSING_WORKER"),
                ],
                cwd=cwd,
                expected_exit=1,
            )
        )
        require(
            missing["error_code"] == "WorkerUnavailable"
            and missing["capabilities"]["worker_available"] is False
            and "PRIVATE_MISSING_WORKER" not in json.dumps(missing),
            "missing worker diagnostic misclassified or leaked its path",
        )
    require(
        results["wheel"]["results"]
        == results["sdist"]["results"]
        == results["npm"]["results"],
        "SDK rendered outputs differ",
    )
    require(
        demos["wheel"] == demos["sdist"] == demos["npm"],
        "SDK complete workflow results differ",
    )
    report = {
        "schema": "cigar.context-distribution-qualification.v1",
        "status": "passed",
        "release_ready": False,
        "diagnostic": prepared["diagnostic"],
        "source_binding": prepared["source_binding"],
        "platform": key,
        "runtime": prepared["runtime"],
        "versions": prepared["versions"],
        "candidate_artifacts": prepared["candidate_artifacts"],
        "network_policy": policy,
        "cases": len(cases),
        "comparisons": len(cases) * 3,
        "rust_successes": sum("snapshot" in row for row in expected),
        "expected_errors": sum("error" in row for row in expected),
        "all_rendered_outputs_equal": True,
        "full_workflow_checks": demos["npm"]["checks"],
        "legacy_exports": {key: value["exports"] for key, value in results.items()},
        "installation_checks": prepared["checks"],
        "offline_checks": runner.checks,
    }
    (output / "qualification.json").write_bytes(canonical_json_bytes(report))
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "status",
                    "platform",
                    "versions",
                    "cases",
                    "comparisons",
                    "release_ready",
                )
            }
        )
    )


def main() -> None:
    require(
        not sys.flags.optimize, "distribution qualification requires assertions enabled"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "offline"))
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=context_platforms.platforms())
    parser.add_argument("--runtime", choices=RUNTIMES, default="current")
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--npm", default="npm")
    parser.add_argument("--stalled-worker", type=Path)
    parser.add_argument("--allow-diagnostic", action="store_true")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "installed distribution qualification")
    if args.phase == "prepare":
        require(
            args.candidate is not None and args.platform is not None,
            "preparation requires a candidate and platform",
        )
        prepare(args)
    else:
        offline(args)


if __name__ == "__main__":
    try:
        main()
    except (
        ReleaseError,
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"installed qualification failed: {error}") from error
