#!/usr/bin/env python3
"""Freeze and offline-verify a context SDK signing handoff; never sign or publish.

This is a candidate-integrity gate, NOT a replacement for release qualification.
Private keys are deliberately absent from this interface. Sign the requested
payloads in the separately approved signing environment using signatures.py.
"""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import re
import tempfile

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    digest_secure_file,
    safe_relative_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    reject_evidence_directory,
    selected_evidence_directory,
)
from verify_release import _load_trust_policy, _verify_envelope


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "cigar.context-sdk-signing-handoff.v1"
MANIFEST = "release-manifest.json"
REPORT = "qualification.json"
CHECKSUMS = "checksums.json"
PURPOSE = "cigar-context-sdk-"
MAX_FILES = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
RELEASE = re.compile(r"0\.10\.0-(rc|beta)\.([1-9][0-9]{0,3})")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def artifact_names(version: str) -> set[str]:
    if version == "0.10.1":
        return {
            "cigar-context-0.10.1.crate",
            "hol-org-cigar-0.10.1.tgz",
            "hol_cigar-0.10.1.tar.gz",
            "hol_cigar-0.10.1-py3-none-macosx_11_0_arm64.whl",
        }
    match = RELEASE.fullmatch(version)
    require(
        match is not None,
        "expected release must be an explicit 0.10.0 rc/beta prerelease or 0.10.1",
    )
    channel, number = match.groups()
    python = f"0.10.0{'rc' if channel == 'rc' else 'b'}{number}"
    return {
        f"cigar-context-{'0.10.0' if channel == 'rc' else version}.crate",
        f"hol-org-cigar-{version}.tgz",
        f"hol_cigar-{python}.tar.gz",
        f"hol_cigar-{python}-py3-none-macosx_11_0_arm64.whl",
    }


def rows(value: object) -> list[dict]:
    require(
        isinstance(value, list) and 0 < len(value) <= MAX_FILES,
        "invalid payload inventory",
    )
    names = set()
    total = 0
    for row in value:
        require(
            isinstance(row, dict) and set(row) == {"file", "sha256", "bytes"},
            "invalid payload fields",
        )
        safe_relative_path(row["file"])
        name = row["file"]
        require(name.casefold() not in names, "duplicate payload name")
        names.add(name.casefold())
        require(
            isinstance(row["sha256"], str)
            and SHA256.fullmatch(row["sha256"]) is not None,
            "invalid payload digest",
        )
        size = row["bytes"]
        require(
            type(size) is int and 0 <= size <= MAX_FILE_BYTES, "invalid payload size"
        )
        total += size
    require(total <= MAX_TOTAL_BYTES, "payload inventory exceeds total byte limit")
    return value


def passed_checks(value: object, required: set[str]) -> None:
    require(
        isinstance(value, list) and 0 < len(value) <= MAX_FILES,
        "missing qualification checks",
    )
    names = set()
    for check in value:
        require(isinstance(check, dict), "invalid qualification check")
        name = check.get("name")
        require(
            isinstance(name, str) and name and name not in names,
            "duplicate or missing check name",
        )
        names.add(name)
        require(
            type(check.get("exit_code")) is int and check["exit_code"] == 0,
            "failed qualification check",
        )
    require(required <= names, "required qualification check missing")


def validate_report(report: dict, expected_release: str) -> None:
    expected = artifact_names(expected_release)
    python = next(
        name
        for name in expected
        if name.startswith("hol_cigar-") and name.endswith(".tar.gz")
    )[10:-7]
    require(isinstance(report, dict), "invalid candidate report")
    require(
        report.get("schema") == "cigar.context-sdk-rc.v1",
        "unsupported candidate schema",
    )
    require(
        report.get("npm") == expected_release and report.get("python") == python,
        "candidate release identity mismatch",
    )
    require(
        report.get("published") is False, "handoff requires an unpublished candidate"
    )
    require(
        report.get("status") == "locally qualified release candidate; not published",
        "candidate was not locally finalized",
    )
    artifacts = rows(report.get("artifacts"))
    require(
        {row["file"] for row in artifacts} == expected,
        "artifact inventory differs from the macOS ARM64 SDK profile",
    )
    evidence = rows(report.get("evidence"))
    require(
        all("/" not in row["file"] and row["file"].endswith(".gz") for row in evidence),
        "invalid retained evidence name",
    )
    require(
        isinstance(report.get("limitations"), list) and bool(report["limitations"]),
        "candidate limitations missing",
    )
    passed_checks(
        report.get("checks"),
        {
            "rust-tests",
            "rust-core-tests",
            "rust-clippy",
            "python-source-tests",
            "typescript-tests",
            "native-build-from-package",
            "python-pack-1",
            "python-pack-2",
            "npm-pack-1",
            "npm-pack-2",
        },
    )
    passed_checks(
        report.get("additional_checks"),
        {
            "generated-sdk-check",
            "operation-surface-parity",
            "release-contract-tests",
            "workflow-static-validation",
            "twine-strict",
        },
    )
    qualification = report.get("qualification")
    require(isinstance(qualification, dict), "qualification missing")
    require(
        qualification.get("schema") == "cigar.context-sdk-qualification.v1"
        and qualification.get("status") == "passed locally; not published",
        "invalid qualification status",
    )
    passed_checks(
        qualification.get("checks"),
        {
            "wheel-tests",
            "sdist-tests",
            "npm-installed-tests",
            "wheel-oracle",
            "sdist-oracle",
            "npm-oracle",
            "baseline-python-tests",
            "baseline-typescript-tests",
            "baseline-python-exports",
            "baseline-typescript-exports",
        },
    )
    for field in (
        "cases",
        "rust_successes",
        "expected_errors",
        "total_result_comparisons",
        "complete_snapshot_comparisons",
        "expected_error_comparisons",
        "python_export_count",
        "typescript_export_count",
    ):
        require(
            type(qualification.get(field)) is int and qualification[field] >= 0,
            "invalid qualification counter",
        )
    require(
        qualification["cases"] >= 172
        and qualification["cases"]
        == qualification["rust_successes"] + qualification["expected_errors"],
        "incomplete oracle corpus",
    )
    require(
        qualification["total_result_comparisons"] == qualification["cases"] * 3
        and qualification["complete_snapshot_comparisons"]
        == qualification["rust_successes"] * 3
        and qualification["expected_error_comparisons"]
        == qualification["expected_errors"] * 3,
        "inconsistent oracle counters",
    )
    require(
        qualification.get("all_legacy_exports_retained") is True
        and qualification.get("all_rendered_outputs_equal") is True,
        "compatibility qualification failed",
    )
    require(
        qualification["python_export_count"] >= 43
        and qualification["typescript_export_count"] >= 104,
        "legacy export inventory incomplete",
    )
    require(
        type(report.get("known_advisories_returned")) is int
        and report["known_advisories_returned"] == 0,
        "unreviewed advisory findings",
    )
    require(
        type(report.get("advisory_packages_checked")) is int
        and report["advisory_packages_checked"] >= 36,
        "advisory inventory incomplete",
    )
    worker = report.get("worker")
    require(
        isinstance(worker, dict)
        and worker.get("protocol") == "cigar.context-worker.v1"
        and worker.get("core_version")
        == ("0.10.0" if "-rc." in expected_release else expected_release)
        and worker.get("sdk_release") == expected_release
        and worker.get("target") == "aarch64-apple-darwin",
        "worker identity mismatch",
    )
    source_archive = next(row for row in artifacts if row["file"].endswith(".crate"))
    require(
        worker.get("source_archive_sha256") == source_archive["sha256"],
        "native source archive mismatch",
    )


def blockers(report: dict) -> list[str]:
    """Unknown release gates cannot be waived by candidate-provided booleans."""
    result = [
        "approved-0.10.0-beta-scope-and-platform-policy",
        "two-independent-clean-native-builds-and-provenance",
        "release-sbom-and-native-license-closure",
        "os-enforced-offline-qualification",
        "current-release-integration-suite-and-security-qualification",
        "approved-production-signing-and-publication-authorization",
    ]
    if not report["npm"].startswith("0.10.0-beta."):
        result.append("beta-versioned-artifacts-not-rc-relabeling")
    if report.get("source_binding", {}).get("clean") is not True:
        result.append("clean-source-bound-build-and-requalification")
    return result


def validate_retained(snapshot: Path, report: dict) -> None:
    """Recompute oracle comparisons from bounded retained data, not summary flags."""
    names = {row["file"] for row in report["evidence"]}
    required = {
        "cases.json.gz",
        "rust-oracle.json.gz",
        "qualification.json.gz",
        "build-release.json.gz",
        "final-advisories.json.gz",
    }
    required.update("build-" + row["name"] + ".log.gz" for row in report["checks"])
    required.update(
        "installed-" + row["name"] + suffix
        for row in report["qualification"]["checks"]
        for suffix in (".stdout.gz", ".stderr.gz")
    )
    required.update(
        "final-" + row["name"] + ".log.gz" for row in report["additional_checks"]
    )
    require(names == required, "retained evidence inventory is not exact")

    def read(name: str) -> bytes:
        with gzip.open(snapshot / "evidence" / name, "rb") as stream:
            payload = stream.read(16 * 1024 * 1024 + 1)
        require(
            len(payload) <= 16 * 1024 * 1024,
            "retained evidence expands beyond the byte limit",
        )
        return payload

    def document(name: str):
        return load_json_bytes(read(name), name)

    require(
        document("qualification.json.gz") == report["qualification"],
        "retained qualification differs from report",
    )
    build = document("build-release.json.gz")
    require(
        isinstance(build, dict)
        and all(
            build.get(key) == report.get(key)
            for key in (
                "checks",
                "artifacts",
                "worker",
                "python",
                "npm",
                "source_binding",
            )
        ),
        "retained build differs from report",
    )
    import hashlib

    for check in report["checks"]:
        require(
            hashlib.sha256(read("build-" + check["name"] + ".log.gz")).hexdigest()
            == check.get("log_sha256"),
            "build log digest mismatch",
        )
    for check in report["additional_checks"]:
        require(
            hashlib.sha256(read("final-" + check["name"] + ".log.gz")).hexdigest()
            == check.get("sha256"),
            "final check log digest mismatch",
        )
    oracle = document("rust-oracle.json.gz")
    cases = document("cases.json.gz")
    require(
        isinstance(oracle, list)
        and isinstance(cases, list)
        and len(oracle) == len(cases) == report["qualification"]["cases"],
        "oracle corpus length mismatch",
    )
    successful = sum(isinstance(row, dict) and "snapshot" in row for row in oracle)
    require(
        successful == report["qualification"]["rust_successes"],
        "oracle success count mismatch",
    )
    rendered = []
    for kind in ("wheel", "sdist", "npm"):
        consumer = document(f"installed-{kind}-oracle.stdout.gz")
        require(
            isinstance(consumer, dict)
            and isinstance(consumer.get("results"), list)
            and len(consumer["results"]) == len(oracle),
            "installed oracle result count mismatch",
        )
        outputs = []
        for actual, expected in zip(consumer["results"], oracle, strict=True):
            require(
                isinstance(actual, dict) and isinstance(expected, dict),
                "invalid oracle row",
            )
            normalized = (
                {"snapshot": actual["snapshot"]} if "snapshot" in actual else actual
            )
            require(normalized == expected, "installed oracle result mismatch")
            if "snapshot" in actual:
                require(
                    isinstance(actual.get("rendered"), str), "rendered output missing"
                )
                outputs.append(actual["rendered"])
        rendered.append(outputs)
    require(
        rendered[0] == rendered[1] == rendered[2], "installed rendered output mismatch"
    )
    advisory = document("final-advisories.json.gz")
    require(
        isinstance(advisory, dict) and advisory.get("findings") == [],
        "retained advisory findings require review",
    )
    queries = advisory.get("queries")
    response = advisory.get("response")
    require(
        isinstance(queries, list)
        and len(queries) == report["advisory_packages_checked"]
        and isinstance(response, dict)
        and isinstance(response.get("results"), list)
        and len(response["results"]) == len(queries)
        and all(
            isinstance(row, dict) and not row.get("vulns")
            for row in response["results"]
        ),
        "advisory response inventory mismatch",
    )


def require_exact_files(root: Path, expected: set[str]) -> None:
    actual = set()
    pending = [root]
    directories = 0
    while pending:
        current = pending.pop()
        directories += 1
        require(directories <= MAX_FILES, "handoff has too many directories")
        with os.scandir(current) as entries:
            for entry in entries:
                require(not entry.is_symlink(), "handoff contains a symlink")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    require(
                        len(pending) <= MAX_FILES, "handoff has too many directories"
                    )
                else:
                    actual.add(str(Path(entry.path).relative_to(root)))
                    require(len(actual) <= MAX_FILES, "handoff has too many files")
    require(actual == expected, "unexpected or missing handoff files")


def request_inventory(manifest: dict) -> list[dict[str, str]]:
    return [
        *(
            {"file": name, "purpose": PURPOSE + "artifact"}
            for name in sorted(artifact_names(manifest["release"]))
        ),
        {"file": REPORT, "purpose": PURPOSE + "evidence"},
        {"file": CHECKSUMS, "purpose": PURPOSE + "checksums"},
        {"file": MANIFEST, "purpose": PURPOSE + "manifest"},
    ]


def stage(candidate: Path, evidence: Path, output: Path, expected_release: str) -> dict:
    """Copy exact archives and retained logs into an immutable external workspace."""
    require(not output.exists(), "handoff output must be new")
    with EvidenceWorkspace.create(output, repository_root=ROOT) as workspace:
        report_binding = workspace.attach_file(candidate / "release.json", REPORT)
        report = load_json(output / REPORT)
        validate_report(report, expected_release)
        # The artifact copy and retained report must describe the same candidate.
        require(
            digest_secure_file(evidence / "release.json").sha256
            == report_binding.sha256,
            "retained report differs from artifact report",
        )
        payloads = [
            {
                "file": REPORT,
                "sha256": report_binding.sha256,
                "bytes": report_binding.bytes,
            }
        ]
        for source_root, prefix, inventory in (
            (candidate, "", report["artifacts"]),
            (evidence, "evidence/", report["evidence"]),
        ):
            for row in inventory:
                name = prefix + row["file"]
                item = workspace.attach_file(
                    source_root / row["file"],
                    name,
                    expected_sha256=row["sha256"],
                    expected_bytes=row["bytes"],
                )
                payloads.append(
                    {"file": name, "sha256": item.sha256, "bytes": item.bytes}
                )
        validate_retained(output, report)
        payloads.sort(key=lambda row: row["file"])
        checksums = workspace.write_json(
            CHECKSUMS,
            {"schema": "cigar.context-sdk-checksums.v1", "payloads": payloads},
        )
        payloads.append(
            {"file": CHECKSUMS, "sha256": checksums.sha256, "bytes": checksums.bytes}
        )
        manifest = {
            "schema": SCHEMA,
            "release": expected_release,
            "profile": "context-sdk-macos-arm64-only",
            "published": False,
            "release_ready": False,
            "release_blockers": blockers(report),
            "payloads": sorted(payloads, key=lambda row: row["file"]),
        }
        binding = workspace.write_json(MANIFEST, manifest)
        return {
            "manifest_sha256": binding.sha256,
            "release": expected_release,
            "release_ready": False,
            "release_blockers": manifest["release_blockers"],
            "signatures_required": request_inventory(manifest),
        }


def _copy_trust(
    workspace: EvidenceWorkspace, policy: Path, expected_sha256: str
) -> Path:
    selected = workspace.root / "trust/policy.json"
    workspace.attach_file(policy, "trust/policy.json", expected_sha256=expected_sha256)
    document = load_json(selected)
    require(
        isinstance(document, dict)
        and isinstance(document.get("keys"), list)
        and 0 < len(document["keys"]) <= 32,
        "invalid trust-policy key inventory",
    )
    names = set()
    for entry in document["keys"]:
        require(isinstance(entry, dict), "invalid trust key")
        name = entry.get("public_key")
        parts = safe_relative_path(name)
        require(
            len(parts) == 1 and name != "policy.json" and name not in names,
            "trust public keys must have distinct basenames",
        )
        names.add(name)
        workspace.attach_file(
            policy.parent / name,
            "trust/" + name,
            expected_sha256=entry.get("public_key_sha256"),
        )
    return selected


def verify(
    handoff: Path,
    policy: Path,
    *,
    expected_release: str,
    manifest_sha256: str,
    policy_sha256: str,
    openssl: Path,
    openssl_sha256: str,
    verification_time: int,
) -> dict:
    """Authenticate a frozen snapshot; never execute a candidate or use its keys."""
    artifact_names(expected_release)
    require(
        SHA256.fullmatch(manifest_sha256) is not None
        and SHA256.fullmatch(policy_sha256) is not None,
        "expected digests must be explicit SHA-256 values",
    )
    require(
        type(verification_time) is int and 0 <= verification_time <= 253_402_300_799,
        "invalid verification time",
    )
    require(
        not policy.resolve(strict=True).is_relative_to(handoff.resolve(strict=True)),
        "trust policy must be independent of the candidate",
    )
    with tempfile.TemporaryDirectory(prefix="cigar-context-sdk-verify-") as raw:
        snapshot = Path(raw).resolve(strict=True) / "snapshot"
        with EvidenceWorkspace.create(snapshot, repository_root=ROOT) as workspace:
            selected_policy = _copy_trust(workspace, policy, policy_sha256)
            trusted = _load_trust_policy(
                selected_policy, openssl_path=openssl, openssl_sha256=openssl_sha256
            )
            workspace.attach_file(
                handoff / MANIFEST, MANIFEST, expected_sha256=manifest_sha256
            )
            workspace.attach_file(
                handoff / "signatures" / (MANIFEST + ".sig.json"),
                "signatures/" + MANIFEST + ".sig.json",
            )
            authenticated_manifest = _verify_envelope(
                snapshot / "signatures" / (MANIFEST + ".sig.json"),
                snapshot,
                trusted,
                PURPOSE + "manifest",
                verification_time,
                openssl_path=openssl,
                openssl_sha256=openssl_sha256,
            )
            require(
                authenticated_manifest == snapshot / MANIFEST,
                "manifest signature payload substitution",
            )
            manifest = load_json(snapshot / MANIFEST)
            require(
                isinstance(manifest, dict)
                and set(manifest)
                == {
                    "schema",
                    "release",
                    "profile",
                    "published",
                    "release_ready",
                    "release_blockers",
                    "payloads",
                },
                "invalid handoff manifest fields",
            )
            require(
                manifest["schema"] == SCHEMA
                and manifest["release"] == expected_release
                and manifest["profile"] == "context-sdk-macos-arm64-only",
                "handoff identity mismatch",
            )
            require(
                manifest["published"] is False and manifest["release_ready"] is False,
                "handoff cannot assert publication or release readiness",
            )
            inventory = rows(manifest["payloads"])
            allowed = artifact_names(expected_release) | {REPORT, CHECKSUMS}
            for row in inventory:
                name = row["file"]
                require(
                    name in allowed
                    or (
                        name.startswith("evidence/")
                        and len(safe_relative_path(name)) == 2
                        and name.endswith(".gz")
                    ),
                    "unrecognized handoff payload",
                )
                workspace.attach_file(
                    handoff / name,
                    name,
                    expected_sha256=row["sha256"],
                    expected_bytes=row["bytes"],
                )
            report = load_json(snapshot / REPORT)
            validate_report(report, expected_release)
            expected = {row["file"]: row for row in report["artifacts"]}
            expected.update(
                {
                    "evidence/" + row["file"]: row | {"file": "evidence/" + row["file"]}
                    for row in report["evidence"]
                }
            )
            actual = {row["file"]: row for row in inventory}
            require(
                set(actual) == set(expected) | {REPORT, CHECKSUMS},
                "handoff payload inventory is not exact",
            )
            require(
                all(actual[name] == row for name, row in expected.items()),
                "handoff differs from qualified hashes",
            )
            checksums = load_json(snapshot / CHECKSUMS)
            require(
                checksums
                == {
                    "schema": "cigar.context-sdk-checksums.v1",
                    "payloads": sorted(
                        (row for row in inventory if row["file"] != CHECKSUMS),
                        key=lambda row: row["file"],
                    ),
                },
                "checksum inventory mismatch",
            )
            require(
                manifest["release_blockers"] == blockers(report),
                "release gates cannot be waived by a signing handoff",
            )
            validate_retained(snapshot, report)
            for request in request_inventory(manifest):
                name = request["file"]
                signature = "signatures/" + name + ".sig.json"
                if name != MANIFEST:
                    workspace.attach_file(handoff / signature, signature)
                    result = _verify_envelope(
                        snapshot / signature,
                        snapshot,
                        trusted,
                        request["purpose"],
                        verification_time,
                        openssl_path=openssl,
                        openssl_sha256=openssl_sha256,
                    )
                    require(result == snapshot / name, "signature payload substitution")
            require_exact_files(
                handoff,
                set(actual)
                | {MANIFEST}
                | {
                    "signatures/" + item["file"] + ".sig.json"
                    for item in request_inventory(manifest)
                },
            )
            return {
                "status": "signatures-and-payloads-verified",
                "release": expected_release,
                "manifest_sha256": manifest_sha256,
                "trust_policy_sha256": policy_sha256,
                "payloads_verified": len(inventory),
                "signatures_verified": len(request_inventory(manifest)),
                "release_ready": False,
                "release_blockers": blockers(report),
                "limitation": "Authenticates the reviewed candidate only; not a release qualification, registry publication, or signed Git tag.",
            }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    prepare = subparsers.add_parser("stage")
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--retained-evidence", type=Path, required=True)
    prepare.add_argument("--expected-release", required=True)
    prepare.add_argument("--evidence-dir", type=Path)
    check = subparsers.add_parser("verify")
    check.add_argument("--handoff", type=Path, required=True)
    check.add_argument("--trust-policy", type=Path, required=True)
    check.add_argument("--expected-release", required=True)
    check.add_argument("--manifest-sha256", required=True)
    check.add_argument("--trust-policy-sha256", required=True)
    check.add_argument("--openssl", type=Path, required=True)
    check.add_argument("--openssl-sha256", required=True)
    check.add_argument("--verification-time", type=int, required=True)
    check.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to stdout-only verification"
    )
    args = parser.parse_args()
    if args.action == "stage":
        output = selected_evidence_directory(args.evidence_dir)
        require(
            output is not None, "stage requires --evidence-dir or CIGAR_EVIDENCE_DIR"
        )
        result = stage(
            args.candidate, args.retained_evidence, output, args.expected_release
        )
    else:
        reject_evidence_directory(args.evidence_dir, "context SDK handoff verification")
        result = verify(
            args.handoff,
            args.trust_policy,
            expected_release=args.expected_release,
            manifest_sha256=args.manifest_sha256,
            policy_sha256=args.trust_policy_sha256,
            openssl=args.openssl,
            openssl_sha256=args.openssl_sha256,
            verification_time=args.verification_time,
        )
    print(canonical_json_bytes(result).decode(), end="")


if __name__ == "__main__":
    try:
        main()
    except (
        ReleaseError,
        EvidenceWorkspaceError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        raise SystemExit(f"context SDK handoff failed: {error}") from error
