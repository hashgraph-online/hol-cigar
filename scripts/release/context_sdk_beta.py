#!/usr/bin/env python3
"""Assemble two independently qualified beta builds or verify exact public bytes.

Only context core/Python/TypeScript are in scope. This does not waive or promote
any Honey release contract. Signing is exclusively in the pinned hosted workflow.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from urllib.parse import quote

import context_sdk_handoff as handoff
from evidence_workspace import EvidenceWorkspace, digest_secure_file
from release_lib import ReleaseError, canonical_json_bytes, reject_evidence_directory

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.10.0-beta.1"
TAG = "v" + VERSION
REPO = "hashgraph-online/hol-cigar"
WORKFLOW = REPO + "/.github/workflows/context-sdk-beta.yml"
MANIFEST = "beta-release-manifest.json"
BUNDLE = "provenance.sigstore.jsonl"
PAYLOADS = handoff.artifact_names(VERSION) | {
    "qualification-evidence.tar.gz",
    "sbom.cdx.json",
    "RELEASE_NOTES.md",
}
SIGNED_FILES = PAYLOADS | {MANIFEST, "SHA256SUMS"}
require = handoff.require


def read_json(path: Path) -> dict:
    binding = digest_secure_file(path)
    require(binding.bytes <= 16 * 1024 * 1024, "JSON exceeds byte limit")
    return json.loads(path.read_bytes())


def inventory(directory: Path, names: set[str]) -> list[dict]:
    result = []
    for name in sorted(names):
        binding = digest_secure_file(directory / name)
        result.append({"file": name, "bytes": binding.bytes, "sha256": binding.sha256})
    return handoff.rows(result)


def validate_build(directory: Path, commit: str) -> dict:
    report = read_json(directory / "artifacts/release.json")
    handoff.validate_report(report, VERSION)
    binding = report.get("source_binding", {})
    require(
        binding.get("commit") == commit and binding.get("clean") is True,
        "build is not bound to the exact clean release commit",
    )
    require(
        binding.get("sha256")
        == hashlib.sha256(canonical_json_bytes(binding.get("files"))).hexdigest(),
        "source input digest mismatch",
    )
    require(
        inventory(directory / "artifacts", handoff.artifact_names(VERSION))
        == report["artifacts"],
        "artifact bytes differ from qualified bytes",
    )
    require(
        read_json(directory / "evidence/release.json") == report,
        "retained report mismatch",
    )
    require(
        inventory(directory / "evidence", {r["file"] for r in report["evidence"]})
        == sorted(report["evidence"], key=lambda r: r["file"]),
        "evidence digest mismatch",
    )
    handoff.validate_retained(directory, report)
    handoff.passed_checks(
        report["qualification"]["checks"],
        {
            "offline-policy-probe",
            "wheel-offline-oracle",
            "sdist-offline-oracle",
            "npm-offline-oracle",
        },
    )
    for kind in ("wheel", "sdist", "npm"):

        def result(suffix: str) -> bytes:
            with gzip.open(
                directory / f"evidence/installed-{kind}-{suffix}.stdout.gz", "rb"
            ) as stream:
                data = stream.read(16 * 1024 * 1024 + 1)
                require(
                    len(data) <= 16 * 1024 * 1024, "offline evidence exceeds byte limit"
                )
                return data

        require(
            json.loads(result("oracle")) == json.loads(result("offline-oracle")),
            "offline consumer differs from qualified oracle",
        )
    return report


def make_sbom(first: Path) -> dict:
    with gzip.open(first / "evidence/build-native-dependencies.log.gz", "rb") as stream:
        payload = stream.read(16 * 1024 * 1024 + 1)
    require(len(payload) <= 16 * 1024 * 1024, "dependency metadata exceeds byte limit")
    packages = json.loads(payload)["packages"]
    components = []
    for package in packages:
        component = {
            "type": "library",
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        components.append(component)
    for ecosystem, name, version, license_id in (
        ("pypi", "protobuf", "6.33.5", "BSD-3-Clause"),
        ("npm", "@bufbuild/protobuf", "2.12.1", "Apache-2.0"),
    ):
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:{ecosystem}/{quote(name, safe='/')}@{version}",
                "licenses": [{"license": {"id": license_id}}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": sorted(components, key=lambda c: c["purl"]),
        "metadata": {
            "properties": [
                {
                    "name": "cigar:scope",
                    "value": "Locked native worker closure plus SDK runtime dependencies; not build tools or the Honey workspace.",
                }
            ]
        },
    }


def assemble(first: Path, second: Path, output: Path, commit: str, run_id: str) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid release commit")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None, "invalid hosted run ID")
    require(first.resolve() != second.resolve(), "two distinct build outputs required")
    reports = [validate_build(directory, commit) for directory in (first, second)]
    require(
        reports[0]["source_binding"] == reports[1]["source_binding"],
        "independent source mismatch",
    )
    require(
        reports[0]["artifacts"] == reports[1]["artifacts"],
        "independent build bytes differ",
    )
    require(
        reports[0]["worker"] == reports[1]["worker"], "independent worker bytes differ"
    )
    with EvidenceWorkspace.create(output, repository_root=ROOT) as workspace:
        for row in reports[0]["artifacts"]:
            workspace.attach_file(
                first / "artifacts" / row["file"],
                row["file"],
                expected_sha256=row["sha256"],
                expected_bytes=row["bytes"],
            )
        workspace.write_json("sbom.cdx.json", make_sbom(first))
        workspace.attach_file(
            ROOT / "docs/release/context-sdk-beta-notes.md", "RELEASE_NOTES.md"
        )
        # Keep both raw evidence inventories; deterministic archive with no local ownership paths.
        with tempfile.TemporaryDirectory(prefix="cigar-beta-evidence-") as temporary:
            packed = Path(temporary).resolve() / "evidence.tar.gz"
            with (
                packed.open("wb") as output_stream,
                gzip.GzipFile(
                    fileobj=output_stream, mode="wb", mtime=0, filename=""
                ) as compressed,
            ):
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for index, (directory, report) in enumerate(
                        zip((first, second), reports, strict=True), 1
                    ):
                        for name in sorted(
                            {"release.json"} | {r["file"] for r in report["evidence"]}
                        ):
                            data = (directory / "evidence" / name).read_bytes()
                            info = tarfile.TarInfo(f"build-{index}/{name}")
                            info.mode, info.size, info.mtime = 0o644, len(data), 0
                            archive.addfile(info, io.BytesIO(data))
            workspace.attach_file(packed, "qualification-evidence.tar.gz")
        manifest = {
            "schema": "cigar.context-sdk-beta.v1",
            "release": VERSION,
            "source_commit": commit,
            "source_binding": reports[0]["source_binding"],
            "profile": "context-core-and-sdk-macos-arm64-beta",
            "python": "0.10.0b1",
            "npm": VERSION,
            "core": VERSION,
            "bundled_native_targets": ["aarch64-apple-darwin"],
            "qualification_run": f"https://github.com/{REPO}/actions/runs/{run_id}",
            "independent_builds": 2,
            "independent_archive_bytes_equal": True,
            "independent_worker_bytes_equal": True,
            "offline_oracle_comparisons_per_build": reports[0]["qualification"][
                "total_result_comparisons"
            ],
            "payloads": inventory(output, PAYLOADS),
            "signature_policy": {
                "repository": REPO,
                "workflow": WORKFLOW,
                "ref": "refs/tags/" + TAG,
                "source_digest": commit,
                "hosted_runners_only": True,
            },
            "limitations": [
                "Beta, not production certification. No full Honey daemon/CLI/MCP release or old Honey gate waiver.",
                "Two fresh GitHub-hosted VMs in one workflow, not two independent trust organizations or a SLSA level claim.",
                "Bundled native execution qualified on macOS ARM64 only; deployment floor is not an older-OS test result.",
                "The portable sdist and other npm platforms need an explicit trusted matching worker for local APIs.",
                "Package/version advisory checks and regression tests are not an exhaustive source security audit.",
                "No new answer-quality, token-reduction or latency claim is made by this release packaging.",
                "PyPI/npm acceptance and npm maintainer approval are separate from the signed GitHub release.",
            ],
        }
        workspace.write_json(MANIFEST, manifest)
        sums = "".join(
            f"{r['sha256']}  {r['file']}\n"
            for r in inventory(output, PAYLOADS | {MANIFEST})
        )
        with tempfile.TemporaryDirectory(prefix="cigar-beta-checksums-") as temporary:
            source = Path(temporary).resolve() / "SHA256SUMS"
            source.write_text(sums)
            workspace.attach_file(source, "SHA256SUMS")
    return manifest


def verify(
    directory: Path, commit: str, attestations: bool, manifest_sha256: str | None = None
) -> dict:
    handoff.require_exact_files(
        directory, SIGNED_FILES | ({BUNDLE} if attestations else set())
    )
    manifest_binding = digest_secure_file(directory / MANIFEST)
    if manifest_sha256 is not None:
        require(
            manifest_binding.sha256 == manifest_sha256,
            "approved manifest digest mismatch",
        )
    document = read_json(directory / MANIFEST)
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None
        and document.get("source_commit") == commit,
        "release commit mismatch",
    )
    require(
        document.get("schema") == "cigar.context-sdk-beta.v1"
        and document.get("release") == VERSION,
        "beta identity mismatch",
    )
    require(
        document.get("payloads") == inventory(directory, PAYLOADS),
        "release payload mismatch",
    )
    sums = "".join(
        f"{r['sha256']}  {r['file']}\n"
        for r in inventory(directory, PAYLOADS | {MANIFEST})
    )
    require(
        (directory / "SHA256SUMS").read_bytes() == sums.encode(),
        "checksum inventory mismatch",
    )
    if attestations:
        for name in sorted(SIGNED_FILES):
            subprocess.run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(directory / name),
                    "--repo",
                    REPO,
                    "--bundle",
                    str(directory / BUNDLE),
                    "--signer-workflow",
                    WORKFLOW,
                    "--source-ref",
                    "refs/tags/" + TAG,
                    "--source-digest",
                    commit,
                    "--signer-digest",
                    commit,
                    "--deny-self-hosted-runners",
                ],
                check=True,
                timeout=120,
            )
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("assemble", "verify"))
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--verify-attestations", action="store_true")
    parser.add_argument("--manifest-sha256")
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable; --directory is explicit"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "beta release assembly/verification")
    try:
        if args.action == "assemble":
            require(
                args.first is not None
                and args.second is not None
                and args.run_id is not None,
                "assembly requires both builds and hosted run ID",
            )
            assemble(args.first, args.second, args.directory, args.commit, args.run_id)
            verify(args.directory, args.commit, False)
        else:
            verify(
                args.directory,
                args.commit,
                args.verify_attestations,
                args.manifest_sha256,
            )
    except (ReleaseError, ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error
    print(
        f"Verified exact {VERSION} bytes; signatures verified: {args.verify_attestations}"
    )


if __name__ == "__main__":
    main()
