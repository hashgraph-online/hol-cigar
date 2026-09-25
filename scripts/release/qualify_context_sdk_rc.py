#!/usr/bin/env python3
"""Clean-install and compare a staged RC, including preserved 0.9.4 SDK baselines."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from release_lib import reject_evidence_directory
import context_sdk_inputs
from context_sdk_cases import build_cases

ROOT = Path(__file__).resolve().parents[2]


def main():
    if sys.flags.optimize:
        raise SystemExit(
            "SDK qualification requires assertions enabled; do not use Python -O"
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--uv", required=True)
    parser.add_argument("--pnpm", required=True)
    parser.add_argument("--npm", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="inapplicable to local diagnostic qualification",
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "local SDK diagnostic qualification")
    staged = json.loads((args.release / "release.json").read_bytes())
    binding = staged.get("source_binding")
    if binding is not None:
        context_sdk_inputs.require_unchanged(
            ROOT, binding, allow_dirty=not binding["clean"]
        )
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    logs = out / "logs"
    logs.mkdir()
    env = os.environ.copy()
    env["PYTHONPATH"] = ""
    env["npm_config_cache"] = str(out / "npm-cache")
    env["PATH"] = str(Path(args.pnpm).absolute().parent) + os.pathsep + env["PATH"]
    env.pop("CIGAR_TEST_WORKER", None)
    env["CIGAR_TEST_STALLED_WORKER"] = str(args.release / "stalled-worker")
    checks = []

    def run(name, command, cwd=out, extra=None):
        print(name, flush=True)
        started = time.monotonic()
        result = subprocess.run(
            [str(x) for x in command],
            cwd=cwd,
            env=env | (extra or {}),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
        )
        (logs / f"{name}.stdout").write_bytes(result.stdout)
        (logs / f"{name}.stderr").write_bytes(result.stderr)
        checks.append(
            {
                "name": name,
                "argv": [str(x) for x in command],
                "exit_code": result.returncode,
                "elapsed_seconds": time.monotonic() - started,
            }
        )
        (out / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(f"{name} failed; inspect {logs}")
        return result.stdout.decode()

    artifacts = args.release / "artifacts"
    run("node-version", ["node", "--version"])
    run("python-version", [sys.executable, "--version"])
    # These are test inputs shared by the *old* suites, not missing runtime assets.
    shutil.copytree(ROOT / "sdk/fixtures", out / "fixtures")
    shutil.copy2(
        ROOT / "sdk/workflow-context-session.v1.json",
        out / "workflow-context-session.v1.json",
    )
    shutil.copy2(ROOT / "sdk/capabilities-v1.json", out / "capabilities-v1.json")
    wheel = artifacts / f"hol_cigar-{staged['python']}-py3-none-macosx_11_0_arm64.whl"
    sdist = artifacts / f"hol_cigar-{staged['python']}.tar.gz"
    npm = artifacts / f"hol-org-cigar-{staged['npm']}.tgz"
    sandbox = [
        "/usr/bin/sandbox-exec",
        "-p",
        "(version 1)(allow default)(deny network*)",
    ]
    if staged.get("channel") in {"beta", "stable"}:
        # A failed connection alone is not sufficient: require the OS policy denial.
        run(
            "offline-policy-probe",
            sandbox
            + [
                sys.executable,
                "-c",
                (
                    "import errno,socket\n"
                    "try: socket.create_connection(('1.1.1.1',443),timeout=2)\n"
                    "except OSError as e: assert e.errno in (errno.EPERM,errno.EACCES), e\n"
                    "else: raise RuntimeError('network denial was not enforced')\n"
                ),
            ],
        )
    with zipfile.ZipFile(wheel) as package:
        metadata_name = next(
            n for n in package.namelist() if n.endswith(".dist-info/WHEEL")
        )
        wheel_metadata = package.read(metadata_name).decode()
        assert "Root-Is-Purelib: false" in wheel_metadata
        assert "Tag: py3-none-macosx_11_0_arm64" in wheel_metadata
        assert not any(".venv/" in n or "__pycache__" in n for n in package.namelist())
    cases = build_cases(ROOT)
    fixtures = out / "cases.json"
    fixtures.write_text(json.dumps(cases, ensure_ascii=False) + "\n")
    expected = []
    print("rust-oracle-172-cases", flush=True)
    for case in cases:
        result = subprocess.run(
            [str(args.cli)],
            input=json.dumps(case).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if result.returncode:
            error = result.stderr.decode().strip().removeprefix("Error: ")
            assert error in {
                "RequiredUnavailable",
                "BudgetUnsatisfiable",
                "LimitExceeded",
                "InvalidInput",
            }, error
            expected.append({"error": error})
        else:
            # Snapshot rendering is compared between SDKs; full snapshot commitments match Rust.
            expected.append({"snapshot": json.loads(result.stdout)})
    (out / "rust-oracle.json").write_text(
        json.dumps(expected, ensure_ascii=False) + "\n"
    )
    consumer_results = {}
    for kind, archive in [("wheel", wheel), ("sdist", sdist)]:
        venv = out / f"{kind}-venv"
        run(f"{kind}-venv", [args.uv, "venv", "--python", sys.executable, venv])
        python = venv / "bin/python"
        run(f"{kind}-install", [args.uv, "pip", "install", "--python", python, archive])
        extra = (
            {}
            if kind == "wheel"
            else {
                "CIGAR_TEST_WORKER": str(
                    args.release / "native/darwin-arm64/cigar-context-worker"
                )
            }
        )
        run(
            f"{kind}-test-tools",
            [args.uv, "pip", "install", "--python", python, "pytest==9.0.3"],
        )
        run(
            f"{kind}-tests",
            [python, "-m", "pytest", ROOT / "sdk/python/tests", "-q"],
            extra=extra,
        )
        command = [python, ROOT / "scripts/release/context_sdk_consumer.py", fixtures]
        if kind == "sdist":
            command.append(extra["CIGAR_TEST_WORKER"])
        consumer_results[kind] = json.loads(run(f"{kind}-oracle", command))
        if staged.get("channel") in {"beta", "stable"}:
            offline = json.loads(run(f"{kind}-offline-oracle", sandbox + command))
            assert offline == consumer_results[kind]
        assert str(venv) in consumer_results[kind]["module"]
        run(f"{kind}-entrypoint", [venv / "bin/cigar-qualify-bundle"])
    npm_consumer = out / "npm-consumer"
    npm_consumer.mkdir()
    (npm_consumer / "package.json").write_text('{"private":true,"type":"module"}\n')
    run(
        "npm-install",
        [args.npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", npm],
        npm_consumer,
    )
    shutil.copy2(
        ROOT / "scripts/release/context-sdk-consumer.mjs", npm_consumer / "consumer.mjs"
    )
    consumer_results["npm"] = json.loads(
        run("npm-oracle", ["node", "consumer.mjs", fixtures], npm_consumer)
    )
    if staged.get("channel") in {"beta", "stable"}:
        offline = json.loads(
            run(
                "npm-offline-oracle",
                sandbox + ["node", "consumer.mjs", fixtures],
                npm_consumer,
            )
        )
        assert offline == consumer_results["npm"]
    installed = npm_consumer / "node_modules/@hol-org/cigar"
    manifest = json.loads((installed / "package.json").read_bytes())
    assert manifest["version"] == staged["npm"] and manifest["publishConfig"][
        "tag"
    ] == (
        "latest" if staged.get("channel") == "stable" else staged.get("channel", "rc")
    )
    assert not any(
        k in manifest["scripts"] for k in ["preinstall", "install", "postinstall"]
    )
    assert not (installed / "dist/tests").exists()
    for path in (installed / "dist").rglob("*.map"):
        source_map = json.loads(path.read_bytes())
        assert len(source_map["sources"]) == len(source_map["sourcesContent"])
        assert all(isinstance(source, str) for source in source_map["sourcesContent"])
    # Test byte-identical installed modules with the source test suite injected in a separate copy.
    test_copy = out / "npm-installed-tests"
    shutil.copytree(installed, test_copy)
    (test_copy / "node_modules").symlink_to(
        npm_consumer / "node_modules", target_is_directory=True
    )
    shutil.copytree(ROOT / "sdk/typescript/dist/tests", test_copy / "dist/tests")
    run(
        "npm-installed-tests",
        ["node", "--test", *sorted((test_copy / "dist/tests").glob("*.test.js"))],
    )
    for name, consumer in consumer_results.items():
        assert len(consumer["results"]) == len(expected)
        for index, (actual, oracle) in enumerate(
            zip(consumer["results"], expected, strict=True)
        ):
            assert (
                {"snapshot": actual["snapshot"]} if "snapshot" in actual else actual
            ) == oracle, (name, index)
    assert (
        consumer_results["wheel"]["results"]
        == consumer_results["sdist"]["results"]
        == consumer_results["npm"]["results"]
    )
    # Exact older source is copied, never modified or installed in-place.
    old = out / "baseline"
    old.mkdir()
    # pnpm's generated .bin shims retain workspace-relative paths to its store.
    # Recreate that dependency-only layout without altering either source tree.
    (out / "node_modules").symlink_to(ROOT / "node_modules", target_is_directory=True)
    shutil.copytree(args.baseline / "sdk/fixtures", old / "fixtures")
    shutil.copy2(
        args.baseline / "sdk/workflow-context-session.v1.json",
        old / "workflow-context-session.v1.json",
    )
    shutil.copy2(
        args.baseline / "sdk/capabilities-v1.json", old / "capabilities-v1.json"
    )
    for language in ["python", "typescript"]:
        shutil.copytree(
            args.baseline / "sdk" / language,
            old / language,
            ignore=shutil.ignore_patterns(
                ".venv", "node_modules", "dist", "__pycache__"
            ),
        )
    old_python_env = out / "baseline-venv"
    run(
        "baseline-python-venv",
        [args.uv, "venv", "--python", sys.executable, old_python_env],
    )
    old_python = old_python_env / "bin/python"
    run(
        "baseline-python-install",
        [args.uv, "pip", "install", "--python", old_python, old / "python"],
    )
    run(
        "baseline-python-test-tools",
        [args.uv, "pip", "install", "--python", old_python, "pytest==9.0.3"],
    )
    run(
        "baseline-python-tests",
        [old_python, "-m", "pytest", old / "python/tests", "-q"],
    )
    old_exports = json.loads(
        run(
            "baseline-python-exports",
            [
                old_python,
                "-c",
                "import json,cigar_sdk;print(json.dumps(cigar_sdk.__all__))",
            ],
        )
    )
    assert set(old_exports) <= set(consumer_results["wheel"]["exports"])
    (old / "typescript/node_modules").symlink_to(
        ROOT / "sdk/typescript/node_modules", target_is_directory=True
    )
    run("baseline-typescript-tests", [args.pnpm, "test"], old / "typescript")
    old_ts_exports = json.loads(
        run(
            "baseline-typescript-exports",
            [
                "node",
                "--input-type=module",
                "-e",
                "console.log(JSON.stringify(Object.keys(await import('./dist/index.js'))))",
            ],
            old / "typescript",
        )
    )
    assert set(old_ts_exports) <= set(consumer_results["npm"]["exports"])
    summary = {
        "schema": "cigar.context-sdk-qualification.v1",
        "status": "passed locally; not published",
        "cases": len(cases),
        "rust_successes": sum("snapshot" in r for r in expected),
        "expected_errors": sum("error" in r for r in expected),
        "total_result_comparisons": len(cases) * 3,
        "complete_snapshot_comparisons": sum("snapshot" in r for r in expected) * 3,
        "expected_error_comparisons": sum("error" in r for r in expected) * 3,
        "python_export_count": len(old_exports),
        "typescript_export_count": len(old_ts_exports),
        "all_legacy_exports_retained": True,
        "all_rendered_outputs_equal": True,
        "checks": checks,
    }
    if binding is not None:
        context_sdk_inputs.require_unchanged(
            ROOT, binding, allow_dirty=not binding["clean"]
        )
    (out / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
