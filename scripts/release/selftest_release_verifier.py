#!/usr/bin/env python3
"""Build and verify a minimal fully signed release fixture without claiming product qualification."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from build_archives import _write_archive
from release_lib import (
    canonical_json_bytes,
    file_reference,
    load_json,
    process_failure_summary,
    repo_root,
    run_bounded,
    sha256_file,
    tree_digest,
    write_bytes,
    write_json,
)
from signatures import public_key_id, sign


EPOCH = 1_700_000_000
REVISION = "a" * 40
SIGNER = "cigar:selftest-release-signer"


def _run(
    arguments: list[str],
    cwd: Path,
    environment: dict[str, str] | None = None,
    expected: int = 0,
) -> subprocess.CompletedProcess[str]:
    raw = run_bounded(
        arguments,
        cwd=cwd,
        env=environment,
        timeout=120,
        max_stdout=8 * 1024 * 1024,
        max_stderr=8 * 1024 * 1024,
    )
    if raw.returncode != expected:
        raise RuntimeError(
            process_failure_summary(raw, "release verifier fixture command")
        )
    result = subprocess.CompletedProcess(
        raw.args,
        raw.returncode,
        raw.stdout.decode("utf-8", errors="replace"),
        raw.stderr.decode("utf-8", errors="replace"),
    )
    return result


def _receipt(
    category: str,
    check: str,
    producer_sha256: str,
    attachment: dict[str, Any],
    metrics: dict[str, int | float] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.qualification-evidence.v1",
        "id": f"selftest-{category}",
        "category": category,
        "source_revision": REVISION,
        "status": "passed",
        "artifact_ids": ["source"],
        "producer": {
            "name": "cigar-release-verifier-selftest",
            "version": "1",
            "tool_sha256": producer_sha256,
            "command": ["python3", "scripts/release/selftest_release_verifier.py"],
            "arguments_redacted": True,
        },
        "checks": [{"id": check, "status": "passed"}],
        "metrics": metrics or {},
        "attachments": [attachment],
    }


def _signature(
    payload: Path,
    purpose: str,
    signature_directory: Path,
    private_key: Path,
    public_key: Path,
) -> Path:
    output = signature_directory / f"{purpose}-{payload.name}.sig.json"
    sign(
        payload,
        private_key,
        public_key,
        output,
        signer_principal=SIGNER,
        purpose=purpose,
        signed_at=EPOCH,
        expires_at=EPOCH + 86_400,
    )
    return output


def main() -> int:
    repository = repo_root()
    python = sys.executable
    with tempfile.TemporaryDirectory(
        prefix="cigar-release-verifier-selftest-"
    ) as directory:
        root = Path(directory)
        packaging = root / "packaging"
        contracts = packaging / "contracts"
        contracts.mkdir(parents=True)
        dist = root / "dist"
        evidence_directory = dist / "evidence"
        signature_directory = dist / "signatures"
        evidence_directory.mkdir(parents=True)
        signature_directory.mkdir(parents=True)

        contract_path = contracts / "source.v1.json"
        contract = {
            "schema_version": "cigar.package-contract.v1",
            "id": "selftest-source-v1",
            "formats": ["tar.gz"],
            "allow": ["RELEASE-METADATA.json", "payload.txt"],
            "deny": [],
            "required": ["RELEASE-METADATA.json", "payload.txt"],
            "symlinks": "forbid",
            "line_endings": "lf",
            "modes": ["0644"],
            "max_entries": 8,
            "max_member_bytes": 1_048_576,
            "max_total_bytes": 2_097_152,
            "content_scan": True,
            "content_scan_exemptions": [],
        }
        write_json(contract_path, contract)
        matrix: dict[str, Any] = {
            "schema_version": "cigar.artifact-matrix.v1",
            "product": "cigar",
            "product_version": "0.1.0",
            "context_abi": "cigar.context.v1",
            "release_state": "release",
            "artifacts": [
                {
                    "id": "source",
                    "kind": "source-archive",
                    "filename": "cigar-0.1.0-source.tar.gz",
                    "contract": "contracts/source.v1.json",
                    "required_for_release": True,
                    "qualification": [
                        "archive-contract",
                        "sbom",
                        "license",
                        "signature",
                        "provenance",
                    ],
                }
            ],
        }
        write_json(packaging / "artifact-matrix.v1.json", matrix)
        qualification_map = load_json(
            repository / "packaging/qualification-category-map.v1.json"
        )
        write_json(packaging / "qualification-category-map.v1.json", qualification_map)
        requirements = load_json(repository / "packaging/release-requirements.v1.json")
        raw_categories = (
            requirements.get("required_evidence_categories")
            if isinstance(requirements, dict)
            else None
        )
        if not isinstance(raw_categories, list) or not all(
            isinstance(value, str) for value in raw_categories
        ):
            raise RuntimeError("repository release requirement categories are invalid")
        categories: list[str] = raw_categories
        write_json(packaging / "release-requirements.v1.json", requirements)
        write_json(
            packaging / "qualification-gaps.v1.json",
            {"schema_version": "cigar.qualification-gaps.v1", "gaps": []},
        )

        for relative, payload in (
            ("Cargo.lock", b"cargo-lock\n"),
            ("pnpm-lock.yaml", b"pnpm-lock\n"),
            ("sdk/python/uv.lock", b"uv-lock\n"),
            ("sdk/go/go.sum", b"go-sum\n"),
        ):
            write_bytes(root / relative, payload)

        payload_path = root / "payload.txt"
        write_bytes(payload_path, b"self-test release payload\n")
        input_digest = tree_digest([("payload.txt", payload_path)])
        source = {
            "revision": REVISION,
            "tree_sha256": input_digest,
            "committed": True,
            "clean": True,
        }
        metadata = {
            "schema_version": "cigar.release-metadata.v1",
            "artifact_id": "source",
            "product_version": "0.1.0",
            "context_abi": "cigar.context.v1",
            "source_date_epoch": EPOCH,
            "source": source,
            "input_tree_sha256": input_digest,
            "input_file_count": 1,
            "contract": "packaging/contracts/source.v1.json",
            "contract_sha256": sha256_file(contract_path),
        }
        artifact = dist / matrix["artifacts"][0]["filename"]
        _write_archive(
            artifact, [("payload.txt", payload_path)], metadata, EPOCH, False
        )
        write_bytes(
            dist / "SHA256SUMS",
            f"{sha256_file(artifact)}  {artifact.name}\n".encode("ascii"),
        )
        build_manifest_path = dist / "build-manifest.json"
        write_json(
            build_manifest_path,
            {
                "schema_version": "cigar.release-build.v1",
                "product_version": "0.1.0",
                "context_abi": "cigar.context.v1",
                "source_date_epoch": EPOCH,
                "source": source,
                "artifacts": [
                    {
                        "id": "source",
                        "path": artifact.name,
                        "sha256": sha256_file(artifact),
                        "bytes": artifact.stat().st_size,
                        "contract": "packaging/contracts/source.v1.json",
                    }
                ],
            },
        )

        component_purl = "pkg:generic/cigar-selftest@0.1.0"
        component_id = "SPDXRef-Package-selftest"
        artifact_record = {
            "name": artifact.name,
            "sha256": sha256_file(artifact),
            "bytes": artifact.stat().st_size,
        }
        artifact_binding = (
            canonical_json_bytes([artifact_record]).decode("utf-8").rstrip("\n")
        )
        write_json(
            dist / "sbom-artifacts.json",
            {
                "schema_version": "cigar.sbom-artifacts.v1",
                "artifacts": [artifact_record],
                "component_count": 1,
            },
        )
        write_json(
            dist / "sbom.spdx.json",
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "cigar-selftest",
                "documentNamespace": "https://cigar.invalid/sbom/selftest",
                "creationInfo": {
                    "created": "2023-11-14T22:13:20Z",
                    "creators": ["Tool: cigar-selftest"],
                },
                "documentDescribes": [component_id],
                "packages": [
                    {
                        "SPDXID": component_id,
                        "name": "cigar-selftest",
                        "versionInfo": "0.1.0",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "licenseConcluded": "Apache-2.0",
                        "licenseDeclared": "Apache-2.0",
                        "copyrightText": "NOASSERTION",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": component_purl,
                            }
                        ],
                    }
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": component_id,
                    }
                ],
                "annotations": [
                    {
                        "annotationDate": "2023-11-14T22:13:20Z",
                        "annotationType": "OTHER",
                        "annotator": "Tool: cigar-release-sbom-v1",
                        "comment": f"CIGAR artifact binding: {artifact_binding}",
                    }
                ],
            },
        )
        write_json(
            dist / "sbom.cyclonedx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
                "version": 1,
                "metadata": {
                    "timestamp": "2023-11-14T22:13:20Z",
                    "component": {
                        "type": "application",
                        "name": "cigar",
                        "version": "0.1.0",
                        "properties": [
                            {"name": "cigar:artifacts", "value": artifact_binding}
                        ],
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": component_purl,
                        "name": "cigar-selftest",
                        "version": "0.1.0",
                        "purl": component_purl,
                        "licenses": [{"expression": "Apache-2.0"}],
                        "properties": [
                            {
                                "name": "cigar:license-policy-status",
                                "value": "accepted-by-policy",
                            }
                        ],
                    }
                ],
            },
        )

        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(EPOCH)
        environment["CIGAR_NO_EGRESS_ENFORCED"] = "1"
        _run(
            [
                python,
                str(repository / "scripts/release/generate_provenance.py"),
                "--root",
                str(root),
                "--artifact",
                str(artifact),
                "--source-archive",
                str(artifact),
                "--source-revision",
                REVISION,
                "--builder-id",
                "cigar:selftest-builder",
                "--workflow-id",
                "cigar.selftest.release-verifier.v1",
                "--network-mode",
                "disabled",
                "--command",
                "selftest-release-build",
                "--source-date-epoch",
                str(EPOCH),
                "--out",
                str(dist / "provenance.json"),
            ],
            root,
            environment,
        )

        check_by_category = {
            "package": "archive-contract",
            "sbom-spdx": "spdx-final-artifact",
            "sbom-cyclonedx": "cyclonedx-final-artifact",
            "license": "license-review",
            "signature": "detached-signature",
            "provenance": "slsa-provenance",
            "docs": "commands-executed",
            "conformance": "conformance-passed",
            "benchmark": "benchmark-passed",
            "operations": "live-exercises",
            "security": "final-artifact-scan",
        }
        evidence_paths: dict[str, Path] = {}
        attachment_paths: dict[str, Path] = {}
        report_directory = dist / "reports"
        report_directory.mkdir()
        producer_sha256 = sha256_file(
            repository / "scripts/release/selftest_release_verifier.py"
        )
        metrics_by_category: dict[str, dict[str, int | float]] = {
            category: {} for category in categories
        }
        gates = (
            requirements.get("metric_gates") if isinstance(requirements, dict) else None
        )
        if not isinstance(gates, list):
            raise RuntimeError("repository release metric gates are invalid")
        for gate in gates:
            if (
                not isinstance(gate, dict)
                or not isinstance(gate.get("category"), str)
                or not isinstance(gate.get("name"), str)
                or not isinstance(gate.get("threshold"), (int, float))
            ):
                raise RuntimeError("repository release metric gate is invalid")
            metrics_by_category[gate["category"]][gate["name"]] = gate["threshold"]
        for category in categories:
            metrics = metrics_by_category[category]
            attachment_path = report_directory / f"raw-{category}.json"
            write_json(
                attachment_path,
                {
                    "schema_version": "cigar.selftest-raw-report.v1",
                    "category": category,
                    "status": "passed",
                },
            )
            attachment_reference = {
                **file_reference(attachment_path, dist),
                "media_type": "application/json",
            }
            path = evidence_directory / f"receipt-{category}.json"
            write_json(
                path,
                _receipt(
                    category,
                    check_by_category.get(category, f"{category}-passed"),
                    producer_sha256,
                    attachment_reference,
                    metrics,
                ),
            )
            evidence_paths[category] = path
            attachment_paths[category] = attachment_path

        key_directory = root / "trust"
        key_directory.mkdir()
        private_key = key_directory / "private.pem"
        public_key = key_directory / "public.pem"
        _run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            root,
        )
        os.chmod(private_key, 0o600)
        _run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            root,
        )
        purposes = [
            "release-artifact",
            "release-checksums",
            "release-sbom",
            "release-provenance",
            "release-conformance",
            "release-benchmark",
            "release-evidence",
        ]
        trust_policy = key_directory / "release-trust-policy.json"
        write_json(
            trust_policy,
            {
                "schema_version": "cigar.release-trust-policy.v1",
                "keys": [
                    {
                        "key_id": public_key_id(public_key),
                        "public_key": "public.pem",
                        "public_key_sha256": sha256_file(public_key),
                        "signer_principal": SIGNER,
                        "purposes": purposes,
                        "status": "active",
                        "active_from": EPOCH - 1,
                    }
                ],
            },
        )

        signature_payloads = [
            (artifact, "release-artifact"),
            (dist / "SHA256SUMS", "release-checksums"),
            (dist / "sbom.spdx.json", "release-sbom"),
            (dist / "sbom.cyclonedx.json", "release-sbom"),
            (dist / "sbom-artifacts.json", "release-sbom"),
            (dist / "provenance.json", "release-provenance"),
            (evidence_paths["conformance"], "release-conformance"),
            (attachment_paths["conformance"], "release-conformance"),
            (evidence_paths["benchmark"], "release-benchmark"),
            (attachment_paths["benchmark"], "release-benchmark"),
        ]
        _ = [
            _signature(payload, purpose, signature_directory, private_key, public_key)
            for payload, purpose in signature_payloads
        ]
        valid_build_manifest = load_json(build_manifest_path)
        invalid_build_manifest = load_json(build_manifest_path)
        invalid_build_manifest["artifacts"][0]["contract"] = (
            "packaging/contracts/wrong.v1.json"
        )
        write_json(build_manifest_path, invalid_build_manifest)
        failed = _run(
            [
                python,
                str(repository / "scripts/release/assemble_evidence.py"),
                "--root",
                str(root),
                "--dist",
                str(dist),
            ],
            root,
            expected=1,
        )
        if "build artifact contract disagrees with the matrix" not in failed.stderr:
            raise RuntimeError(
                "mismatched build-manifest contract failed for an unexpected reason"
            )
        write_json(build_manifest_path, valid_build_manifest)
        release_path = dist / "release-evidence.json"
        _run(
            [
                python,
                str(repository / "scripts/release/assemble_evidence.py"),
                "--root",
                str(root),
                "--dist",
                str(dist),
            ],
            root,
        )
        if not release_path.is_file():
            raise RuntimeError("release evidence assembler did not emit its manifest")
        sign(
            release_path,
            private_key,
            public_key,
            dist / "release-evidence.json.sig.json",
            signer_principal=SIGNER,
            purpose="release-evidence",
            signed_at=EPOCH,
            expires_at=EPOCH + 86_400,
        )

        report = root / "verification-report.json"
        _run(
            [
                python,
                str(repository / "scripts/release/verify_release.py"),
                str(dist),
                "--root",
                str(root),
                "--trust-policy",
                str(trust_policy),
                "--verification-time",
                str(EPOCH + 1),
                "--report",
                str(report),
            ],
            root,
        )
        if not report.is_file():
            raise RuntimeError("release verifier self-test did not emit its report")

        original = artifact.read_bytes()
        write_bytes(artifact, original + b"tampered")
        failed = _run(
            [
                python,
                str(repository / "scripts/release/verify_release.py"),
                str(dist),
                "--root",
                str(root),
                "--trust-policy",
                str(trust_policy),
                "--verification-time",
                str(EPOCH + 1),
            ],
            root,
            expected=1,
        )
        if "digest or size mismatch" not in failed.stderr:
            raise RuntimeError("tampered release failed for an unexpected reason")

        write_bytes(artifact, original)
        unreferenced = dist / "unreferenced-payload.bin"
        write_bytes(unreferenced, b"not part of the signed release inventory\n")
        failed = _run(
            [
                python,
                str(repository / "scripts/release/verify_release.py"),
                str(dist),
                "--root",
                str(root),
                "--trust-policy",
                str(trust_policy),
                "--verification-time",
                str(EPOCH + 1),
            ],
            root,
            expected=1,
        )
        if "release directory inventory mismatch" not in failed.stderr:
            raise RuntimeError(
                "unreferenced release payload failed for an unexpected reason"
            )
        unreferenced.unlink()

        docs_attachment = attachment_paths["docs"]
        attachment_original = docs_attachment.read_bytes()
        write_bytes(docs_attachment, attachment_original + b"tampered")
        failed = _run(
            [
                python,
                str(repository / "scripts/release/verify_release.py"),
                str(dist),
                "--root",
                str(root),
                "--trust-policy",
                str(trust_policy),
                "--verification-time",
                str(EPOCH + 1),
            ],
            root,
            expected=1,
        )
        if "attachment digest or size mismatch" not in failed.stderr:
            raise RuntimeError("tampered raw report failed for an unexpected reason")

    print(
        "signed release verifier self-test passed; mismatched build contract, tampered artifact/raw report, "
        "and unreferenced payload were rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
