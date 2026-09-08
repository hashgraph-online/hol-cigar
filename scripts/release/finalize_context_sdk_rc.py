#!/usr/bin/env python3
"""Retain qualified local archives/evidence with hashes; never publish or overwrite a release."""

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import Request, urlopen

from release_lib import reject_evidence_directory
import context_sdk_inputs

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sys.flags.optimize:
        raise SystemExit(
            "SDK qualification requires assertions enabled; do not use Python -O"
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--qualification", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--uv", required=True)
    parser.add_argument("--actionlint", required=True)
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to local diagnostic retention"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "local SDK diagnostic retention")
    release = json.loads((args.release / "release.json").read_bytes())
    binding = release.get("source_binding")
    if binding is not None:
        context_sdk_inputs.require_unchanged(
            ROOT, binding, allow_dirty=not binding["clean"]
        )
    qualification = json.loads((args.qualification / "qualification.json").read_bytes())
    assert all(
        check["exit_code"] == 0 for check in release["checks"] + qualification["checks"]
    )
    assert qualification["status"] == "passed locally; not published"
    # Derive counts from retained raw results, not from a manually entered summary.
    oracle = json.loads((args.qualification / "rust-oracle.json").read_bytes())
    for kind in ["wheel", "sdist", "npm"]:
        actual = json.loads(
            (args.qualification / f"logs/{kind}-oracle.stdout").read_bytes()
        )["results"]
        assert len(actual) == len(oracle)
        for result, expected in zip(actual, oracle, strict=True):
            assert (
                {"snapshot": result["snapshot"]} if "snapshot" in result else result
            ) == expected
    assert (
        qualification["complete_snapshot_comparisons"]
        == sum("snapshot" in x for x in oracle) * 3
    )
    for artifact in release["artifacts"]:
        assert sha(args.release / "artifacts" / artifact["file"]) == artifact["sha256"]
    checks_dir = args.qualification / "final-checks"
    checks_dir.mkdir(exist_ok=False)
    additional = []

    def run(name, command):
        print(name, flush=True)
        result = subprocess.run(
            [str(x) for x in command],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
        log = checks_dir / f"{name}.log"
        log.write_bytes(result.stdout)
        additional.append(
            {
                "name": name,
                "exit_code": result.returncode,
                "sha256": sha(log),
                "argv": [str(x) for x in command],
            }
        )
        if result.returncode:
            raise SystemExit(f"{name} failed: {log}")

    run("generated-sdk-check", [sys.executable, "sdk/generate_clients.py", "--check"])
    run(
        "operation-surface-parity",
        [sys.executable, "tools/quality/operation_surface_parity.py", "--quiet"],
    )
    run(
        "release-contract-tests",
        [
            sys.executable,
            "-m",
            "unittest",
            "scripts.release.tests.test_balanced_compatibility",
            "tools.quality.tests.test_pypi_honey_workflow",
            "scripts.release.tests.test_verify_npm_sdk",
        ],
    )
    run(
        "workflow-static-validation",
        [
            args.actionlint,
            "-shellcheck=",
            "-pyflakes=",
            ".github/workflows/context-sdk-rc.yml",
            ".github/workflows/npm-sdk-readiness.yml",
            ".github/workflows/fast-ci.yml",
            ".github/workflows/context-sdk-beta.yml",
            ".github/workflows/publish-hol-cigar.yml",
            ".github/workflows/stage-hol-cigar-npm.yml",
        ],
    )
    run(
        "twine-strict",
        [
            args.uv,
            "tool",
            "run",
            "--from",
            "twine==6.2.0",
            "twine",
            "check",
            "--strict",
            args.release
            / f"artifacts/hol_cigar-{release['python']}-py3-none-macosx_11_0_arm64.whl",
            args.release / f"artifacts/hol_cigar-{release['python']}.tar.gz",
        ],
    )
    run("diff-whitespace", ["git", "diff", "--check"])
    packages = json.loads(
        (args.release / "native/darwin-arm64/dependencies.json").read_bytes()
    )
    queries = [
        {
            "package": {"name": p["name"], "ecosystem": "crates.io"},
            "version": p["version"],
        }
        for p in packages
        if (p["source"] or "").startswith("registry+")
    ]
    queries += [
        {"package": {"name": "protobuf", "ecosystem": "PyPI"}, "version": "6.33.5"},
        {
            "package": {"name": "@bufbuild/protobuf", "ecosystem": "npm"},
            "version": "2.12.1",
        },
    ]
    print("public-dependency-advisory-lookup", flush=True)
    request = Request(
        "https://api.osv.dev/v1/querybatch",
        json.dumps({"queries": queries}).encode(),
        {"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        answer = json.load(response)
    assert len(answer["results"]) == len(queries)
    advisory = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "queries": queries,
        "response": answer,
        "findings": [
            q
            for q, row in zip(queries, answer["results"], strict=True)
            if row.get("vulns")
        ],
        "limitations": "Public package/version lookup only; not a source security audit or absence guarantee.",
    }
    (checks_dir / "advisories.json").write_text(json.dumps(advisory, indent=2) + "\n")
    if advisory["findings"]:
        raise SystemExit("Known advisories require review before local RC finalization")
    if binding is not None:
        context_sdk_inputs.require_unchanged(
            ROOT, binding, allow_dirty=not binding["clean"]
        )
    args.artifacts.mkdir(parents=True, exist_ok=False)
    args.evidence.mkdir(parents=True, exist_ok=False)
    for artifact in release["artifacts"]:
        shutil.copy2(
            args.release / "artifacts" / artifact["file"],
            args.artifacts / artifact["file"],
        )
    retained = []

    def retain(source, name):
        target = args.evidence / (name + ".gz")
        target.write_bytes(gzip.compress(source.read_bytes(), mtime=0))
        retained.append(
            {"file": target.name, "sha256": sha(target), "bytes": target.stat().st_size}
        )

    for path in sorted((args.release / "logs").iterdir()):
        retain(path, "build-" + path.name)
    for path in sorted((args.qualification / "logs").iterdir()):
        retain(path, "installed-" + path.name)
    for path in sorted(checks_dir.iterdir()):
        retain(path, "final-" + path.name)
    for name in ["cases.json", "rust-oracle.json", "qualification.json"]:
        retain(args.qualification / name, name)
    retain(args.release / "release.json", "build-release.json")
    source_files = {
        ROOT / name
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "pnpm-lock.yaml",
            "sdk/generate_clients.py",
            "sdk/local-context-release.v1.json",
            "sdk/fixtures/stalled-worker.rs",
            "sdk/capabilities-v1.json",
            "sdk/workflow-context-session.v1.json",
            ".github/workflows/context-sdk-rc.yml",
            ".github/workflows/npm-sdk-readiness.yml",
            ".github/workflows/fast-ci.yml",
        ]
    }
    excluded = {
        ".venv",
        "node_modules",
        "dist",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
    for directory in [
        ROOT / "crates/cigar-context",
        ROOT / "sdk/python",
        ROOT / "sdk/typescript",
    ]:
        for parent, dirs, names in os.walk(directory):
            dirs[:] = [name for name in dirs if name not in excluded]
            source_files.update(
                Path(parent) / name for name in names if not name.startswith(".")
            )
    source_files.update((ROOT / "scripts/release").glob("*context*.*"))
    source_hashes = {
        str(path.relative_to(ROOT)): sha(path) for path in sorted(source_files)
    }
    final = release | {
        "status": "locally qualified release candidate; not published",
        "qualification": qualification,
        "additional_checks": additional,
        "advisory_packages_checked": len(queries),
        "known_advisories_returned": 0,
        "source_sha256": source_hashes,
        "evidence": retained,
        "qualified_platform": release["native_qualified_host"],
        "limitations": [
            "This diagnostic report alone does not establish hosted or independent build provenance; see the separate signed beta manifest.",
            "No bundled native Linux/Windows qualification.",
            "Platform binary has macOS 11 deployment floor, not a test result on macOS 11.",
            "Exact tested Python/Node versions are in retained logs; other supported versions are not individually qualified.",
            "Source distribution requires an explicit local worker for local context APIs.",
            "IPC adds startup, serialization and process memory versus in-process Rust.",
            "No new model answer-quality or token-reduction claim is made by SDK packaging.",
            "Unsigned, unpublished candidate; source_binding records clean/dirty state when available. Honey 0.9.4 publication remains separate.",
        ],
    }
    (args.evidence / "release.json").write_text(json.dumps(final, indent=2) + "\n")
    shutil.copy2(args.evidence / "release.json", args.artifacts / "release.json")
    (args.artifacts / "SHA256SUMS").write_text(
        "".join(
            f"{sha(path)}  {path.name}\n"
            for path in sorted(args.artifacts.iterdir())
            if path.is_file()
        )
    )
    print(
        json.dumps(
            {
                "artifacts": str(args.artifacts),
                "evidence": str(args.evidence),
                "source_files": len(source_hashes),
                "retained_logs": len(retained),
                "status": final["status"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
