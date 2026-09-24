#!/usr/bin/env python3
"""Assemble and verify the complete, qualified CIGAR 0.11.0 distribution."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import gzip
import hashlib
import io
import json
import ntpath
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen

import context_distribution as distribution
import context_platforms
import context_sdk_beta as legacy
from qualify_context_distribution import RUNTIMES
from context_sdk_cases import build_cases
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    reject_evidence_directory,
)

ROOT = distribution.ROOT
require = distribution.require


class DistributionProfile(legacy.ReleaseProfile):
    @property
    def schema(self) -> str:
        return "cigar.context-sdk-distribution-release.v1"

    @property
    def payloads(self) -> set[str]:
        return distribution.artifact_names(set(context_platforms.platforms())) | {
            "qualification-evidence.tar.gz",
            "sbom.cdx.json",
            "sbom.spdx.json",
            "RELEASE_NOTES.md",
        }


PROFILE = DistributionProfile(
    "0.11.0",
    "0.11.0",
    "stable",
    legacy.REPO + "/.github/workflows/context-sdk-release.yml",
    "release-manifest.json",
    "docs/release/context-sdk-0.11.0-notes.md",
)


def raw_json(files: dict[str, bytes], name: str):
    require(name in files, f"missing retained qualification input: {name}")
    return load_json_bytes(files[name], name)


def check_logs(
    files: dict[str, bytes], prefix: str, checks: list, expected: dict[str, int]
) -> None:
    require(
        {item["name"] for item in checks} == expected.keys()
        and len(checks) == len(expected),
        "required qualification checks missing",
    )
    for item in checks:
        require(
            item["exit_code"] == item["expected_exit"] == expected[item["name"]],
            "qualification check failed",
        )
        for stream in ("stdout", "stderr"):
            content = files[f"{prefix}{item['name']}.{stream}"]
            require(
                {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                == item[stream],
                "qualification log changed",
            )


def validate_qualification(
    files: dict[str, bytes], prefix: str, candidate: dict, key: str, runtime: str
) -> dict:
    report = raw_json(files, prefix + "qualification.json")
    prepared = raw_json(files, prefix + "prepare.json")
    require(
        report.get("schema") == "cigar.context-distribution-qualification.v1"
        and report.get("status") == "passed"
        and report.get("diagnostic") is False,
        "invalid installed qualification",
    )
    require(
        prepared.get("schema") == "cigar.context-distribution-install.v1"
        and prepared.get("status") == "installed-tests-passed"
        and prepared.get("diagnostic") is False
        and all(
            prepared[field] == report[field]
            for field in ("platform", "runtime", "versions")
        ),
        "invalid retained installation",
    )
    require(
        report["platform"] == key
        and report["runtime"] == runtime
        and report["versions"] == RUNTIMES[runtime],
        "installed runtime/platform mismatch",
    )
    require(
        report["source_binding"]
        == prepared["source_binding"]
        == candidate["source_binding"]
        and report["candidate_artifacts"]
        == prepared["candidate_artifacts"]
        == candidate["artifacts"],
        "installed qualification refers to different source or archives",
    )
    install_names = {
        f"{kind}-{check}": 0
        for kind in ("wheel", "sdist")
        for check in ("venv", "install", "tests", "legacy-entrypoint")
    }
    install_names.update({"npm-install": 0, "npm-installed-tests": 0})
    require(
        prepared["checks"] == report["installation_checks"],
        "retained installation checks differ",
    )
    check_logs(files, prefix + "logs/", report["installation_checks"], install_names)
    offline_names = {
        f"{kind}-{check}": (1 if check == "missing-worker" else 0)
        for kind in ("wheel", "sdist", "npm")
        for check in ("offline-oracle", "doctor", "demo", "missing-worker")
    }
    check_logs(files, prefix + "offline/logs/", report["offline_checks"], offline_names)
    cases = raw_json(files, prefix + "cases.json")
    for name in ("cases", "programs"):
        content = files[prefix + name + ".json"]
        require(
            prepared[name]
            == {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()},
            "retained installation input changed",
        )
    require(
        cases == build_cases(ROOT),
        "retained cases differ from the authored and seeded qualification suite",
    )
    oracle = raw_json(files, prefix + "offline/rust-oracle.json")
    require(
        len(cases) == len(oracle) == report["cases"] == 172
        and report["comparisons"] == 516,
        "installed oracle comparison count mismatch",
    )
    require(
        report["rust_successes"] == sum("snapshot" in row for row in oracle)
        and report["expected_errors"] == sum("error" in row for row in oracle),
        "oracle outcome counters differ",
    )
    policy = raw_json(files, prefix + "offline/network-policy.json")
    expected_policy = (
        "macos-sandbox-deny-network"
        if key.startswith("darwin-")
        else (
            "linux-network-namespace-none"
            if key.startswith("linux-")
            else "windows-outbound-program-firewall"
        )
    )
    addresses = {"1.1.1.1", "127.0.0.1"} if key.startswith("darwin-") else {"1.1.1.1"}
    require(
        policy == report["network_policy"]
        and policy["kind"] == expected_policy
        and policy["provider_calls"] == 0
        and len(policy["probes"]) == len(addresses)
        and {row["address"] for row in policy["probes"]} == addresses
        and all(row["denied"] is True for row in policy["probes"]),
        "missing offline policy evidence",
    )
    # errno values are platform-specific; these are the values recorded by the
    # corresponding hosted OS, independent of the verifier's own platform.
    allowed_errors = (
        {1, 13}
        if key.startswith("darwin-")
        else (
            {1, 13, 101}
            if key.startswith("linux-")
            else {None, errno.EACCES, errno.EPERM, errno.ETIMEDOUT, 10013, 10060}
        )
    )
    require(
        all(row["errno"] in allowed_errors for row in policy["probes"]),
        "probe did not demonstrate OS network denial",
    )
    if key == "win32-x64":
        state = policy["verified_rules"]
        require(
            len(state["profiles"]) == 3
            and all(row["Enabled"] is True for row in state["profiles"]),
            "Windows firewall profiles were not enabled",
        )
        blocked = {
            ntpath.normcase(row["Program"])
            for row in state["rules"]
            if row["Enabled"] == "True"
            and row["Action"] == "Block"
            and row["Direction"] == "Outbound"
        }
        programs = raw_json(files, prefix + "programs.json")
        require(
            bool(programs) and {ntpath.normcase(name) for name in programs} <= blocked,
            "Windows firewall did not cover all consumer programs",
        )
    results, demos = [], []
    for kind in ("wheel", "sdist", "npm"):
        actual = raw_json(files, prefix + f"offline/logs/{kind}-offline-oracle.stdout")
        require(
            len(actual["results"]) == len(oracle),
            "retained consumer result count mismatch",
        )
        for item, expected in zip(actual["results"], oracle, strict=True):
            require(
                ({"snapshot": item["snapshot"]} if "snapshot" in item else item)
                == expected,
                "retained SDK result differs from native oracle",
            )
        require(
            actual["exports"] == report["legacy_exports"][kind],
            "retained export inventory mismatch",
        )
        doctor = raw_json(files, prefix + f"offline/logs/{kind}-doctor.stdout")
        require(
            doctor["status"] == "ready"
            and doctor["compile_verified"] is True
            and doctor["capabilities"]["requires_hol_services"] is False,
            "installed diagnostic failed",
        )
        demo = raw_json(files, prefix + f"offline/logs/{kind}-demo.stdout")
        require(
            demo["status"] == "passed"
            and demo["reviewer"] == "scripted-fixture"
            and demo["checks"] == report["full_workflow_checks"]
            and len(demo["checks"]) >= 13,
            "complete installed workflow missing",
        )
        missing = raw_json(files, prefix + f"offline/logs/{kind}-missing-worker.stdout")
        require(
            missing["error_code"] == "WorkerUnavailable"
            and missing["compile_verified"] is False
            and "PRIVATE_MISSING_WORKER" not in json.dumps(missing),
            "missing-worker control failed",
        )
        results.append(actual["results"])
        demos.append(demo)
    require(
        results[0] == results[1] == results[2] and demos[0] == demos[1] == demos[2],
        "cross-language behavior mismatch",
    )
    return report


def make_sbom(first: Path, candidate: dict) -> dict:
    components = {}
    for key in candidate["platforms"]:
        directory = first / "workers" / key / "native" / key
        for package in load_json(directory / "dependencies.json"):
            purl = f"pkg:cargo/{package['name']}@{package['version']}"
            components[purl] = {
                "type": "library",
                "name": package["name"],
                "version": package["version"],
                "purl": purl,
                "licenses": [{"expression": package["license"]}]
                if package["license"]
                else [],
            }
    for ecosystem, name, version, license_id in (
        ("pypi", "protobuf", "6.33.5", "BSD-3-Clause"),
        ("npm", "@bufbuild/protobuf", "2.12.1", "Apache-2.0"),
    ):
        purl = f"pkg:{ecosystem}/{quote(name, safe='/')}@{version}"
        components[purl] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "licenses": [{"license": {"id": license_id}}],
        }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [components[key] for key in sorted(components)],
        "metadata": {
            "properties": [
                {
                    "name": "cigar:scope",
                    "value": "Native runtime closure for all seven targets and SDK runtime dependencies; excludes build tools and operating-system libraries.",
                }
            ]
        },
    }


def advisories(sbom: dict) -> dict:
    queries = []
    for item in sbom["components"]:
        if item["name"] == "cigar-context":
            continue
        ecosystem = (
            "crates.io"
            if item["purl"].startswith("pkg:cargo/")
            else ("PyPI" if item["purl"].startswith("pkg:pypi/") else "npm")
        )
        queries.append(
            {
                "package": {"name": item["name"], "ecosystem": ecosystem},
                "version": item["version"],
            }
        )
    request = Request(
        "https://api.osv.dev/v1/querybatch",
        canonical_json_bytes({"queries": queries}),
        {"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=60) as response:
        result = json.load(response)
    require(
        len(result["results"]) == len(queries),
        "incomplete dependency advisory response",
    )
    findings = [
        query
        for query, row in zip(queries, result["results"], strict=True)
        if row.get("vulns")
    ]
    require(not findings, "runtime dependency advisories require review before release")
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "queries": queries,
        "response": result,
        "findings": findings,
        "limitation": "Public package/version advisory lookup; not a source security audit or absence guarantee.",
    }


def assemble(args) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.commit) is not None
        and re.fullmatch(r"[0-9]+", args.run_id or "") is not None,
        "assembly requires an exact commit and hosted run ID",
    )
    comparison = distribution.compare_candidates(args.first, args.second, args.commit)
    candidate = load_json(args.first / "candidate.json")
    # Preserve the older public SDK compatibility suite, then bind its SDK code
    # to the exact code packaged here (native workers have their own full matrix).
    old = legacy.validate_build(args.legacy, args.commit, legacy.STABLE)
    old_npm = distribution.archive_files(
        args.legacy / "artifacts/hol-org-cigar-0.11.0.tgz"
    )
    new_npm = distribution.archive_files(
        args.first / "artifacts/hol-org-cigar-0.11.0.tgz"
    )
    require(
        {
            name: value
            for name, value in old_npm.items()
            if not name.startswith("package/native/")
        }
        == {
            name: value
            for name, value in new_npm.items()
            if not name.startswith("package/native/")
        },
        "legacy compatibility tested different SDK code",
    )
    retained = {
        "first/candidate.json": (args.first / "candidate.json").read_bytes(),
        "second/candidate.json": (args.second / "candidate.json").read_bytes(),
        "comparison.json": canonical_json_bytes(comparison),
        "legacy/release.json": canonical_json_bytes(old),
    }
    for builder, directory in (("first", args.first), ("second", args.second)):
        for path in sorted((directory / "logs").iterdir()):
            retained[f"{builder}/logs/{path.name}"] = path.read_bytes()
        for key in candidate["platforms"]:
            worker = directory / "workers" / key
            for relative in (
                "build.json",
                "checks.json",
                f"native/{key}/manifest.json",
                f"native/{key}/dependencies.json",
                f"native/{key}/THIRD_PARTY_NOTICES.txt",
            ):
                retained[f"{builder}/workers/{key}/{relative}"] = (
                    worker / relative
                ).read_bytes()
            for path in sorted((worker / "logs").iterdir()):
                retained[f"{builder}/workers/{key}/logs/{path.name}"] = (
                    path.read_bytes()
                )
    qualifications = []
    for key in candidate["platforms"]:
        for runtime in RUNTIMES:
            name = f"context-installed-{key}-{runtime}"
            directory = args.qualifications / name
            for path in sorted(directory.rglob("*")):
                if path.is_file():
                    distribution.file_record(path)
                    retained[
                        f"installed/{key}/{runtime}/{path.relative_to(directory).as_posix()}"
                    ] = path.read_bytes()
            qualifications.append(
                validate_qualification(
                    retained, f"installed/{key}/{runtime}/", candidate, key, runtime
                )
            )
    sbom = make_sbom(args.first, candidate)
    retained["advisories.json"] = canonical_json_bytes(advisories(sbom))
    output = args.directory.absolute()
    output.mkdir(parents=True, exist_ok=False)
    for name in distribution.artifact_names(set(candidate["platforms"])):
        shutil.copyfile(args.first / "artifacts" / name, output / name)
    with (output / "qualification-evidence.tar.gz").open("xb") as stream:
        with gzip.GzipFile(
            fileobj=stream, mode="wb", filename="", mtime=0
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, content in sorted(retained.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.mtime = len(content), 0o644, 0
                    archive.addfile(item, io.BytesIO(content))
    (output / "sbom.cdx.json").write_bytes(canonical_json_bytes(sbom))
    spdx = legacy.make_spdx(
        sbom, args.commit, candidate["source_binding"]["source_date_epoch"], PROFILE
    )
    spdx["creationInfo"]["creators"] = ["Tool: cigar-context-sdk-distribution"]
    (output / "sbom.spdx.json").write_bytes(canonical_json_bytes(spdx))
    shutil.copyfile(ROOT / PROFILE.notes, output / "RELEASE_NOTES.md")
    document = {
        "schema": PROFILE.schema,
        "release": PROFILE.version,
        "source_commit": args.commit,
        "source_binding": candidate["source_binding"],
        "qualification_run": f"https://github.com/{legacy.REPO}/actions/runs/{args.run_id}",
        "independent_builds": 2,
        "platforms": candidate["platforms"],
        "runtime_pairs": RUNTIMES,
        "installed_qualifications": len(qualifications),
        "offline_result_comparisons": sum(row["comparisons"] for row in qualifications),
        "payloads": legacy.inventory(output, PROFILE.payloads),
        "limitations": [
            "Fixture reviewers test the answer-review contract, not real-model factuality.",
            "The portable source install requires an explicit trusted matching worker.",
            "Windows firewall evidence covers external outbound traffic; Windows loopback denial is not claimed.",
        ],
    }
    (output / PROFILE.manifest).write_bytes(canonical_json_bytes(document))
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{row['sha256']}  {row['file']}\n"
            for row in legacy.inventory(output, PROFILE.payloads | {PROFILE.manifest})
        )
    )
    verify(output, args.commit, False)
    print(
        json.dumps(
            {
                "status": "qualified; awaiting signed publication",
                "platforms": document["platforms"],
                "installed_qualifications": len(qualifications),
            }
        )
    )


def verify(
    directory: Path, commit: str, attestations: bool, manifest_sha256: str | None = None
) -> dict:
    document = legacy.verify(directory, commit, attestations, manifest_sha256, PROFILE)
    require(
        document["platforms"] == sorted(context_platforms.platforms())
        and document["runtime_pairs"] == RUNTIMES
        and document["independent_builds"] == 2
        and document["installed_qualifications"] == 14
        and document["offline_result_comparisons"] == 14 * 516,
        "release qualification matrix is incomplete",
    )
    retained = distribution.archive_files(directory / "qualification-evidence.tar.gz")
    first, second = (
        raw_json(retained, "first/candidate.json"),
        raw_json(retained, "second/candidate.json"),
    )
    require(
        first["source_binding"]
        == second["source_binding"]
        == document["source_binding"]
        and first["source_binding"]["commit"] == commit
        and first["source_binding"]["clean"] is True,
        "retained source bindings differ",
    )
    require(
        first["diagnostic"] is False
        and second["diagnostic"] is False
        and first["builder"] == "first"
        and second["builder"] == "second",
        "retained builds are diagnostic or not distinct",
    )
    require(
        first["artifacts"]
        == second["artifacts"]
        == {
            name: distribution.file_record(directory / name)
            for name in distribution.artifact_names(set(first["platforms"]))
        },
        "released archives differ from independent builds",
    )
    with tempfile.TemporaryDirectory(prefix="cigar-public-archive-check-") as temporary:
        archives = Path(temporary)
        for name in distribution.artifact_names(set(first["platforms"])):
            shutil.copyfile(directory / name, archives / name)
        distribution.verify_packages(archives, first["workers"])
    for key in document["platforms"]:
        require(
            first["workers"][key]["worker"] == second["workers"][key]["worker"],
            "retained native bytes differ",
        )
        for runtime in RUNTIMES:
            validate_qualification(
                retained, f"installed/{key}/{runtime}/", first, key, runtime
            )
    advisory = raw_json(retained, "advisories.json")
    require(
        not advisory["findings"]
        and all(not row.get("vulns") for row in advisory["response"]["results"]),
        "retained dependency advisories need review",
    )
    return document


def main() -> None:
    require(not sys.flags.optimize, "release qualification requires assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "verify"))
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--qualifications", type=Path)
    parser.add_argument("--legacy", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--verify-attestations", action="store_true")
    parser.add_argument(
        "--check-advisories",
        action="store_true",
        help="Repeat the public dependency advisory lookup before publication",
    )
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "stable distribution release")
    if args.command == "assemble":
        require(
            all(
                getattr(args, key) is not None
                for key in ("first", "second", "qualifications", "legacy", "run_id")
            ),
            "assembly requires complete native, SDK and installed evidence",
        )
        assemble(args)
    else:
        result = verify(
            args.directory, args.commit, args.verify_attestations, args.manifest_sha256
        )
        if args.check_advisories:
            advisories(load_json(args.directory / "sbom.cdx.json"))
        print(
            json.dumps(
                {
                    "status": "verified",
                    "release": result["release"],
                    "signed": args.verify_attestations,
                }
            )
        )


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
        raise SystemExit(f"release verification failed: {error}") from error
