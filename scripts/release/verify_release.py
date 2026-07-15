#!/usr/bin/env python3
"""Perform the complete local offline verification of a CIGAR release directory."""

from __future__ import annotations

import argparse
import math
import os
import re
import time
from pathlib import Path
from typing import Any

from assemble_evidence import _enforce_metric_gates, _require_artifact_qualification
from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    repo_root,
    require_distinct_output,
    resolve_beneath,
    safe_relative_path,
    sha256_file,
    validate_qualification_policy,
    validate_release_policy_documents,
)
from signatures import _secure_openssl, public_key_id, verify as verify_signature
from verify_package import verify as verify_package


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument(
        "--trust-policy",
        type=Path,
        required=True,
        help="offline key scope/status policy and adjacent public roots",
    )
    parser.add_argument(
        "--openssl",
        type=Path,
        required=True,
        help="absolute path to the independently reviewed OpenSSL executable",
    )
    parser.add_argument(
        "--openssl-sha256",
        required=True,
        help="lowercase SHA-256 of the independently reviewed OpenSSL executable",
    )
    parser.add_argument(
        "--verification-time",
        type=int,
        help="Unix time for signature validity; defaults to the current time",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="external private evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="create-new report path, relative to --evidence-dir when selected",
    )
    return parser.parse_args()


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment:
        argument_path = argument.expanduser()
        environment_path = Path(environment).expanduser()
        if os.fspath(argument_path) != os.fspath(environment_path):
            raise ReleaseError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; "
                "provide one evidence directory"
            )
    if argument is not None:
        return argument.expanduser()
    if environment:
        return Path(environment).expanduser()
    return None


def _is_same_or_beneath(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


class _ReportOutput:
    """Pinned secure destination for one offline-verification report."""

    def __init__(
        self,
        workspace: EvidenceWorkspace,
        relative: str,
    ) -> None:
        self.workspace = workspace
        self.relative = relative

    @classmethod
    def open(
        cls,
        arguments: argparse.Namespace,
        *,
        repository_root: Path,
        dist: Path,
    ) -> _ReportOutput | None:
        if arguments.report is None:
            _selected_evidence_directory(arguments)
            return None

        evidence_root = _selected_evidence_directory(arguments)
        requested = arguments.report.expanduser()
        if evidence_root is not None:
            if requested.is_absolute():
                raise ReleaseError(
                    "--report must be relative when an evidence directory is selected"
                )
            parts = safe_evidence_path(os.fspath(requested))
            relative = "/".join(parts)
        else:
            if not requested.is_absolute():
                raise ReleaseError(
                    "--report must be absolute unless --evidence-dir or "
                    "CIGAR_EVIDENCE_DIR is selected"
                )
            parts = safe_evidence_path(requested.name)
            relative = "/".join(parts)
            evidence_root = requested.parent

        tentative_report = evidence_root.joinpath(*relative.split("/"))
        require_distinct_output(
            tentative_report, [arguments.trust_policy], "release verification"
        )
        if evidence_root.is_absolute() and _is_same_or_beneath(tentative_report, dist):
            raise ReleaseError(
                "release verification report must be written outside the "
                "verified directory"
            )
        workspace = EvidenceWorkspace.create(
            evidence_root,
            repository_root=repository_root,
        )
        try:
            report_path = workspace.root.joinpath(*relative.split("/"))
            if _is_same_or_beneath(report_path, dist):
                raise ReleaseError(
                    "release verification report must be written outside the "
                    "verified directory"
                )
            return cls(workspace, relative)
        except BaseException:
            workspace.close()
            raise

    def publish(self, report: dict[str, Any]) -> None:
        self.workspace.write_json(self.relative, report)

    def close(self) -> None:
        self.workspace.close()


def _referenced_file(dist: Path, reference: dict[str, Any]) -> Path:
    if not isinstance(reference, dict):
        raise ReleaseError("release evidence file reference is not an object")
    path = resolve_beneath(dist, reference.get("path", ""))
    if not path.is_file():
        raise ReleaseError(f"release evidence path is not a regular file: {path}")
    if sha256_file(path) != reference.get(
        "sha256"
    ) or path.stat().st_size != reference.get("bytes"):
        raise ReleaseError(
            f"release evidence digest or size mismatch: {path.relative_to(dist)}"
        )
    return path


def _parse_checksums(path: Path, dist: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        fields = line.split("  ", 1)
        if (
            len(fields) != 2
            or len(fields[0]) != 64
            or any(character not in "0123456789abcdef" for character in fields[0])
        ):
            raise ReleaseError(f"invalid checksum manifest line {number}")
        relative = safe_relative_path(fields[1])
        if relative in result:
            raise ReleaseError(f"duplicate checksum manifest path: {relative}")
        target = resolve_beneath(dist, relative)
        if sha256_file(target) != fields[0]:
            raise ReleaseError(f"checksum manifest mismatch: {relative}")
        result[relative] = fields[0]
    if not result:
        raise ReleaseError("checksum manifest is empty")
    return result


def _find_unique(dist: Path, basename: str) -> Path:
    candidates = [path for path in dist.rglob(basename) if path.is_file()]
    if len(candidates) != 1:
        raise ReleaseError(f"expected exactly one {basename}, found {len(candidates)}")
    return candidates[0]


def _signature_payload(dist: Path, envelope: dict[str, Any]) -> Path:
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise ReleaseError("signature envelope payload reference is invalid")
    name = safe_relative_path(payload["name"])
    direct = dist / name
    if direct.is_file():
        return direct
    return _find_unique(dist, Path(name).name)


def _load_trust_policy(
    path: Path, *, openssl_path: Path, openssl_sha256: str
) -> dict[str, dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError("release trust policy must be a regular, non-symlink file")
    document = load_json(path)
    if not isinstance(document, dict) or set(document) != {"schema_version", "keys"}:
        raise ReleaseError("release trust policy has an unexpected shape")
    if document.get("schema_version") != "cigar.release-trust-policy.v1":
        raise ReleaseError("unsupported release trust policy")
    entries = document.get("keys")
    if not isinstance(entries, list) or not entries:
        raise ReleaseError("release trust policy has no keys")
    trusted: dict[str, dict[str, Any]] = {}
    required = {
        "key_id",
        "public_key",
        "public_key_sha256",
        "signer_principal",
        "purposes",
        "status",
        "active_from",
    }
    allowed = required | {"retired_at"}
    for entry in entries:
        if not isinstance(entry, dict) or (
            set(entry) != required and set(entry) != allowed
        ):
            raise ReleaseError("release trust-policy key has an unexpected shape")
        identifier = entry.get("key_id")
        if not isinstance(identifier, str) or identifier in trusted:
            raise ReleaseError(
                "release trust policy has an invalid or duplicate key id"
            )
        relative = safe_relative_path(entry.get("public_key", ""))
        unresolved = path.parent.joinpath(*relative.split("/"))
        if unresolved.is_symlink():
            raise ReleaseError(f"trusted public key must not be a symlink: {relative}")
        key_path = resolve_beneath(path.parent, relative)
        if not key_path.is_file() or sha256_file(key_path) != entry.get(
            "public_key_sha256"
        ):
            raise ReleaseError(f"trusted public key digest mismatch: {relative}")
        if (
            public_key_id(
                key_path,
                openssl_path=openssl_path,
                openssl_sha256=openssl_sha256,
            )
            != identifier
        ):
            raise ReleaseError(f"trusted public key id mismatch: {relative}")
        principal = entry.get("signer_principal")
        purposes = entry.get("purposes")
        status = entry.get("status")
        active_from = entry.get("active_from")
        retired_at = entry.get("retired_at")
        if (
            not isinstance(principal, str)
            or not principal
            or principal != principal.strip()
            or len(principal.encode("utf-8")) > 256
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in principal
            )
        ):
            raise ReleaseError(f"trusted signer principal is invalid: {identifier}")
        if (
            not isinstance(purposes, list)
            or not purposes
            or not all(
                isinstance(value, str)
                and re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", value) is not None
                for value in purposes
            )
            or len(set(purposes)) != len(purposes)
        ):
            raise ReleaseError(f"trusted purpose scope is invalid: {identifier}")
        if status not in {"active", "retired", "revoked"}:
            raise ReleaseError(f"trusted key status is invalid: {identifier}")
        if (
            not isinstance(active_from, int)
            or isinstance(active_from, bool)
            or active_from < 0
            or active_from > 253_402_300_799
        ):
            raise ReleaseError(f"trusted key activation time is invalid: {identifier}")
        if status == "retired":
            if (
                not isinstance(retired_at, int)
                or isinstance(retired_at, bool)
                or retired_at <= active_from
                or retired_at > 253_402_300_799
            ):
                raise ReleaseError(
                    f"retired key has no valid retirement time: {identifier}"
                )
        elif retired_at is not None:
            raise ReleaseError(
                f"only retired keys may declare retired_at: {identifier}"
            )
        trusted[identifier] = {**entry, "public_key_path": key_path}
    return trusted


def _verify_envelope(
    envelope_path: Path,
    dist: Path,
    trusted: dict[str, dict[str, Any]],
    expected_purpose: str,
    verification_time: int,
    *,
    openssl_path: Path,
    openssl_sha256: str,
) -> Path:
    envelope = load_json(envelope_path)
    key_id = envelope.get("key_id") if isinstance(envelope, dict) else None
    if key_id not in trusted:
        raise ReleaseError(
            f"signature uses an untrusted key: {envelope_path.relative_to(dist)}"
        )
    trust = trusted[key_id]
    if trust["status"] == "revoked":
        raise ReleaseError(
            f"signature uses a revoked key: {envelope_path.relative_to(dist)}"
        )
    payload = _signature_payload(dist, envelope)
    unsigned = verify_signature(
        envelope_path,
        payload,
        trust["public_key_path"],
        expected_purpose=expected_purpose,
        expected_signer=trust["signer_principal"],
        verification_time=verification_time,
        openssl_path=openssl_path,
        openssl_sha256=openssl_sha256,
    )
    if expected_purpose not in trust["purposes"]:
        raise ReleaseError(
            f"signing key is outside its purpose scope: {expected_purpose}"
        )
    if unsigned["signed_at"] < trust["active_from"]:
        raise ReleaseError("signature predates trusted-key activation")
    if trust["status"] == "retired" and unsigned["signed_at"] >= trust["retired_at"]:
        raise ReleaseError("signature was created after trusted-key retirement")
    return payload


def _validate_receipt(
    path: Path,
    reference: dict[str, Any],
    dist: Path,
    revision: str,
    artifact_ids: set[str],
) -> dict[str, Any]:
    receipt = load_json(path)
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != "cigar.qualification-evidence.v1"
    ):
        raise ReleaseError(f"unsupported qualification receipt: {path}")
    required = {
        "schema_version",
        "id",
        "category",
        "source_revision",
        "status",
        "artifact_ids",
        "producer",
        "checks",
        "metrics",
        "attachments",
    }
    if set(receipt) != required:
        raise ReleaseError(f"qualification receipt has an unexpected shape: {path}")
    if receipt.get("id") != reference.get("id") or receipt.get(
        "category"
    ) != reference.get("category"):
        raise ReleaseError(f"qualification receipt identity mismatch: {path}")
    if (
        receipt.get("source_revision") != revision
        or reference.get("source_revision") != revision
    ):
        raise ReleaseError(f"stale qualification receipt: {path}")
    if receipt.get("status") != "passed" or reference.get("status") != "passed":
        raise ReleaseError(f"non-passing qualification receipt: {path}")
    receipt_artifacts = receipt.get("artifact_ids")
    if (
        not isinstance(receipt_artifacts, list)
        or not receipt_artifacts
        or len(set(receipt_artifacts)) != len(receipt_artifacts)
        or any(value not in artifact_ids for value in receipt_artifacts)
    ):
        raise ReleaseError(
            f"qualification receipt references unknown artifacts: {path}"
        )
    if sorted(receipt_artifacts) != sorted(reference.get("artifact_ids", [])):
        raise ReleaseError(f"qualification receipt artifact binding mismatch: {path}")
    checks = receipt.get("checks")
    if (
        not isinstance(checks, list)
        or not checks
        or any(
            not isinstance(check, dict)
            or set(check) != {"id", "status"}
            or check.get("status") != "passed"
            for check in checks
        )
    ):
        raise ReleaseError(
            f"qualification receipt contains skipped/failed checks: {path}"
        )
    check_ids = [check.get("id") for check in checks]
    if not all(isinstance(value, str) and value for value in check_ids) or len(
        set(check_ids)
    ) != len(check_ids):
        raise ReleaseError(
            f"qualification receipt has invalid or duplicate check ids: {path}"
        )
    metrics = receipt.get("metrics")
    if not isinstance(metrics, dict) or any(
        not isinstance(name, str)
        or not name
        or not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        for name, value in metrics.items()
    ):
        raise ReleaseError(f"qualification receipt metrics are invalid: {path}")
    producer = receipt.get("producer")
    if not isinstance(producer, dict) or set(producer) != {
        "name",
        "version",
        "tool_sha256",
        "command",
        "arguments_redacted",
    }:
        raise ReleaseError(f"qualification receipt producer is invalid: {path}")
    if (
        not all(
            isinstance(producer.get(name), str)
            and producer[name]
            and len(producer[name].encode("utf-8")) <= 128
            for name in ("name", "version")
        )
        or any(
            any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in producer[name]
            )
            for name in ("name", "version")
        )
        or not isinstance(producer.get("tool_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", producer["tool_sha256"]) is None
        or not isinstance(producer.get("command"), list)
        or not producer["command"]
        or not all(
            isinstance(value, str) and value and len(value.encode("utf-8")) <= 1024
            for value in producer["command"]
        )
        or any(
            any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            for value in producer["command"]
        )
        or producer.get("arguments_redacted") is not True
    ):
        raise ReleaseError(f"qualification receipt producer fields are invalid: {path}")
    attachments = receipt.get("attachments")
    if not isinstance(attachments, list) or not attachments:
        raise ReleaseError(f"qualification receipt attachments are empty: {path}")
    attachment_paths: set[str] = set()
    for attachment_reference in attachments:
        if not isinstance(attachment_reference, dict) or set(attachment_reference) != {
            "path",
            "sha256",
            "bytes",
            "media_type",
        }:
            raise ReleaseError(f"qualification receipt attachment is invalid: {path}")
        relative = safe_relative_path(attachment_reference.get("path", ""))
        if relative in attachment_paths:
            raise ReleaseError(
                f"qualification receipt attachment is duplicated: {relative}"
            )
        attachment_paths.add(relative)
        attachment = resolve_beneath(dist, relative)
        if attachment == path.resolve() or not attachment.is_file():
            raise ReleaseError(
                f"qualification receipt attachment is missing or self-referential: {relative}"
            )
        if (
            sha256_file(attachment) != attachment_reference.get("sha256")
            or attachment.stat().st_size != attachment_reference.get("bytes")
            or attachment.stat().st_size <= 0
        ):
            raise ReleaseError(
                f"qualification receipt attachment digest or size mismatch: {relative}"
            )
        media_type = attachment_reference.get("media_type")
        if (
            not isinstance(media_type, str)
            or re.fullmatch(
                r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[a-z0-9=._+-]+)?",
                media_type,
            )
            is None
        ):
            raise ReleaseError(
                f"qualification receipt attachment media type is invalid: {relative}"
            )
    if receipt.get("metrics") != reference.get("metrics"):
        raise ReleaseError(f"qualification receipt metric binding mismatch: {path}")
    return receipt


def _subject_map(values: Any, label: str) -> dict[str, str]:
    if not isinstance(values, list) or not values:
        raise ReleaseError(f"{label} is empty or invalid")
    result: dict[str, str] = {}
    for value in values:
        if not isinstance(value, dict) or set(value) != {"name", "digest"}:
            raise ReleaseError(f"{label} contains an invalid subject")
        name = safe_relative_path(value.get("name", ""))
        digest = value.get("digest")
        if (
            not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", digest["sha256"]) is None
        ):
            raise ReleaseError(f"{label} contains an invalid digest: {name}")
        if name in result:
            raise ReleaseError(f"{label} contains a duplicate name: {name}")
        result[name] = digest["sha256"]
    return result


def _validate_provenance(
    path: Path,
    artifacts: dict[str, Path],
    root: Path,
    revision: str,
    source_date_epoch: int,
) -> None:
    provenance = load_json(path)
    if not isinstance(provenance, dict) or set(provenance) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        raise ReleaseError("provenance statement has an unexpected shape")
    if (
        provenance.get("_type") != "https://in-toto.io/Statement/v1"
        or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
    ):
        raise ReleaseError("unsupported provenance statement")
    subjects = _subject_map(provenance.get("subject"), "provenance subjects")
    expected_subjects = {path.name: sha256_file(path) for path in artifacts.values()}
    if subjects != expected_subjects:
        raise ReleaseError(
            "provenance subject set differs from the release artifact set"
        )
    predicate = provenance.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {
        "buildDefinition",
        "runDetails",
    }:
        raise ReleaseError("provenance predicate has an unexpected shape")
    definition = predicate.get("buildDefinition")
    if not isinstance(definition, dict) or set(definition) != {
        "buildType",
        "externalParameters",
        "internalParameters",
        "resolvedDependencies",
    }:
        raise ReleaseError("provenance build definition has an unexpected shape")
    if (
        definition.get("buildType")
        != "https://cigar.invalid/build-types/release-archive/v1"
    ):
        raise ReleaseError("unsupported provenance build type")
    external = definition.get("externalParameters")
    required_external = {
        "commands",
        "sourceDateEpoch",
        "sourceRevision",
        "sourceArchive",
        "workflowId",
    }
    if not isinstance(external, dict) or set(external) != required_external:
        raise ReleaseError("provenance external parameters have an unexpected shape")
    commands = external.get("commands")
    workflow = external.get("workflowId")
    if (
        not isinstance(commands, list)
        or not commands
        or not all(
            isinstance(value, str) and value and value == value.strip()
            for value in commands
        )
    ):
        raise ReleaseError("provenance commands are invalid")
    if not isinstance(workflow, str) or not workflow or workflow != workflow.strip():
        raise ReleaseError("provenance workflow id is invalid")
    if (
        external.get("sourceRevision") != revision
        or external.get("sourceDateEpoch") != source_date_epoch
    ):
        raise ReleaseError(
            "provenance source revision or epoch disagrees with release evidence"
        )
    if "source" not in artifacts:
        raise ReleaseError(
            "artifact matrix has no source archive for provenance binding"
        )
    source_archive = _subject_map(
        [external.get("sourceArchive")], "provenance source archive"
    )
    expected_source = {artifacts["source"].name: sha256_file(artifacts["source"])}
    if source_archive != expected_source:
        raise ReleaseError("provenance source archive binding is invalid")
    internal = definition.get("internalParameters")
    if not isinstance(internal, dict) or set(internal) != {
        "network",
        "locale",
        "timezone",
    }:
        raise ReleaseError("provenance internal parameters have an unexpected shape")
    if (
        internal.get("network") != "disabled"
        or internal.get("timezone") != "UTC"
        or internal.get("locale") != "C"
    ):
        raise ReleaseError(
            "release provenance does not attest the required isolated environment"
        )
    materials = _subject_map(
        definition.get("resolvedDependencies"), "provenance materials"
    )
    if not all(
        materials.get(name) == digest for name, digest in expected_source.items()
    ):
        raise ReleaseError("provenance materials omit the exact source archive")
    for relative in (
        "Cargo.lock",
        "pnpm-lock.yaml",
        "sdk/python/uv.lock",
        "sdk/go/go.sum",
    ):
        lock = resolve_beneath(root, relative)
        if materials.get(relative) != sha256_file(lock):
            raise ReleaseError(f"provenance materials omit or mismatch {relative}")
    details = predicate.get("runDetails")
    if not isinstance(details, dict) or set(details) != {"builder", "metadata"}:
        raise ReleaseError("provenance run details have an unexpected shape")
    builder = details.get("builder")
    if (
        not isinstance(builder, dict)
        or set(builder) != {"id"}
        or not isinstance(builder.get("id"), str)
        or not builder["id"]
    ):
        raise ReleaseError("provenance builder identity is invalid")
    metadata = details.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "invocationId",
        "startedOnSourceDateEpoch",
        "finishedOnSourceDateEpoch",
    }:
        raise ReleaseError("provenance run metadata has an unexpected shape")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("invocationId"))) is None:
        raise ReleaseError("provenance invocation id is invalid")
    if (
        metadata.get("startedOnSourceDateEpoch") != source_date_epoch
        or metadata.get("finishedOnSourceDateEpoch") != source_date_epoch
    ):
        raise ReleaseError("provenance run timestamps disagree with SOURCE_DATE_EPOCH")


def _validate_sboms(
    dist: Path, artifacts: dict[str, Path], product_version: str
) -> set[Path]:
    binding_path = _find_unique(dist, "sbom-artifacts.json")
    binding = load_json(binding_path)
    if (
        not isinstance(binding, dict)
        or set(binding) != {"schema_version", "artifacts", "component_count"}
        or binding.get("schema_version") != "cigar.sbom-artifacts.v1"
    ):
        raise ReleaseError("SBOM artifact binding has an unexpected shape")
    records = binding.get("artifacts")
    if not isinstance(records, list) or not records:
        raise ReleaseError("SBOM artifact binding is empty")
    bound: set[tuple[str, str, int]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"name", "sha256", "bytes"}:
            raise ReleaseError("SBOM artifact binding record is invalid")
        name = record.get("name")
        digest = record.get("sha256")
        size = record.get("bytes")
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise ReleaseError("SBOM artifact binding record has invalid fields")
        item = (name, digest, size)
        if item in bound:
            raise ReleaseError("SBOM artifact binding contains duplicates")
        bound.add(item)
    if len({path.name for path in artifacts.values()}) != len(artifacts):
        raise ReleaseError("release artifacts have duplicate basenames")
    expected_records = sorted(
        (
            {
                "name": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in artifacts.values()
        ),
        key=lambda item: str(item["name"]),
    )
    expected = {
        (record["name"], record["sha256"], record["bytes"])
        for record in expected_records
    }
    if bound != expected or records != expected_records:
        raise ReleaseError(
            "SBOM artifact binding differs from the release artifact set"
        )
    artifact_binding = (
        canonical_json_bytes(expected_records).decode("utf-8").rstrip("\n")
    )
    count = binding.get("component_count")
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        raise ReleaseError("SBOM component count is invalid")

    spdx = load_json(_find_unique(dist, "sbom.spdx.json"))
    if (
        not isinstance(spdx, dict)
        or spdx.get("spdxVersion") != "SPDX-2.3"
        or spdx.get("dataLicense") != "CC0-1.0"
        or spdx.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise ReleaseError("SPDX document identity is invalid")
    annotations = spdx.get("annotations")
    binding_comments = [
        annotation.get("comment")
        for annotation in annotations or []
        if isinstance(annotation, dict)
        and annotation.get("annotator") == "Tool: cigar-release-sbom-v1"
    ]
    if binding_comments != [f"CIGAR artifact binding: {artifact_binding}"]:
        raise ReleaseError("SPDX document does not bind the exact release artifact set")
    packages = spdx.get("packages")
    if not isinstance(packages, list) or len(packages) != count:
        raise ReleaseError("SPDX package count disagrees with SBOM binding")
    spdx_ids: set[str] = set()
    spdx_purls: set[str] = set()
    for package in packages:
        if (
            not isinstance(package, dict)
            or not isinstance(package.get("SPDXID"), str)
            or package["SPDXID"] in spdx_ids
        ):
            raise ReleaseError("SPDX package id is invalid or duplicated")
        spdx_ids.add(package["SPDXID"])
        if package.get("licenseConcluded") in {None, "NOASSERTION"} or package.get(
            "licenseDeclared"
        ) in {None, "NOASSERTION"}:
            raise ReleaseError(
                f"SPDX package license remains unreviewed: {package.get('name')}"
            )
        references = package.get("externalRefs")
        purls = [
            value.get("referenceLocator")
            for value in references or []
            if isinstance(value, dict) and value.get("referenceType") == "purl"
        ]
        if len(purls) != 1 or not isinstance(purls[0], str) or purls[0] in spdx_purls:
            raise ReleaseError("SPDX package purl is missing or duplicated")
        spdx_purls.add(purls[0])
    described = spdx.get("documentDescribes")
    if (
        not isinstance(described, list)
        or set(described) != spdx_ids
        or len(described) != len(spdx_ids)
    ):
        raise ReleaseError("SPDX documentDescribes does not match its package set")

    cyclonedx = load_json(_find_unique(dist, "sbom.cyclonedx.json"))
    if (
        not isinstance(cyclonedx, dict)
        or cyclonedx.get("bomFormat") != "CycloneDX"
        or cyclonedx.get("specVersion") != "1.6"
        or cyclonedx.get("version") != 1
    ):
        raise ReleaseError("CycloneDX document identity is invalid")
    cdx_metadata = cyclonedx.get("metadata")
    cdx_root = cdx_metadata.get("component") if isinstance(cdx_metadata, dict) else None
    root_properties = cdx_root.get("properties") if isinstance(cdx_root, dict) else None
    artifact_properties = [
        value.get("value")
        for value in root_properties or []
        if isinstance(value, dict) and value.get("name") == "cigar:artifacts"
    ]
    if (
        not isinstance(cdx_root, dict)
        or cdx_root.get("name") != "cigar"
        or cdx_root.get("version") != product_version
        or artifact_properties != [artifact_binding]
    ):
        raise ReleaseError(
            "CycloneDX document does not bind the exact release artifact set and version"
        )
    components = cyclonedx.get("components")
    if not isinstance(components, list) or len(components) != count:
        raise ReleaseError("CycloneDX component count disagrees with SBOM binding")
    cdx_purls: set[str] = set()
    for component in components:
        if (
            not isinstance(component, dict)
            or not isinstance(component.get("purl"), str)
            or component["purl"] in cdx_purls
        ):
            raise ReleaseError("CycloneDX component purl is invalid or duplicated")
        if component.get("bom-ref") != component["purl"]:
            raise ReleaseError("CycloneDX component bom-ref differs from its purl")
        cdx_purls.add(component["purl"])
        licenses = component.get("licenses")
        if (
            not isinstance(licenses, list)
            or not licenses
            or any(
                not isinstance(value, dict)
                or value.get("expression") in {None, "NOASSERTION"}
                for value in licenses
            )
        ):
            raise ReleaseError(
                f"CycloneDX component license remains unreviewed: {component.get('name')}"
            )
        properties = component.get("properties")
        statuses = [
            value.get("value")
            for value in properties or []
            if isinstance(value, dict)
            and value.get("name") == "cigar:license-policy-status"
        ]
        if statuses != ["accepted-by-policy"]:
            raise ReleaseError(
                f"CycloneDX component is outside license policy: {component.get('name')}"
            )
    if cdx_purls != spdx_purls:
        raise ReleaseError("SPDX and CycloneDX component sets disagree")
    return {
        binding_path.resolve(),
        _find_unique(dist, "sbom.spdx.json").resolve(),
        _find_unique(dist, "sbom.cyclonedx.json").resolve(),
    }


def _run_verification(
    arguments: argparse.Namespace, report_output: _ReportOutput | None
) -> int:
    root = arguments.root.resolve()
    dist = arguments.directory.resolve()
    if not dist.is_dir():
        raise ReleaseError("release directory does not exist")
    verification_time = (
        int(time.time())
        if arguments.verification_time is None
        else arguments.verification_time
    )
    if verification_time < 0 or verification_time > 253_402_300_799:
        raise ReleaseError("verification time must be a non-negative Unix timestamp")
    if re.fullmatch(r"[0-9a-f]{64}", arguments.openssl_sha256) is None:
        raise ReleaseError("reviewed OpenSSL SHA-256 must be 64 lowercase hex digits")
    reviewed_openssl = _secure_openssl(arguments.openssl, arguments.openssl_sha256)
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ReleaseError(
                f"release directory contains a symlink: {path.relative_to(dist)}"
            )
    release_path = dist / "release-evidence.json"
    release = load_json(release_path)
    if (
        not isinstance(release, dict)
        or release.get("schema_version") != "cigar.release-evidence.v1"
    ):
        raise ReleaseError("unsupported release evidence")
    if set(release) != {
        "schema_version",
        "product_version",
        "context_abi",
        "source_date_epoch",
        "source",
        "build",
        "artifacts",
        "evidence",
        "signatures",
    }:
        raise ReleaseError("release evidence has an unexpected shape")
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    requirements = load_json(root / "packaging/release-requirements.v1.json")
    gaps = load_json(root / "packaging/qualification-gaps.v1.json")
    validate_release_policy_documents(matrix, requirements, gaps)
    qualification_mapping = load_json(
        resolve_beneath(root, requirements["qualification_category_map"])
    )
    validate_qualification_policy(qualification_mapping)
    if release.get("product_version") != matrix.get("product_version") or release.get(
        "context_abi"
    ) != matrix.get("context_abi"):
        raise ReleaseError("release evidence version/ABI mismatch")
    if matrix.get("release_state") != "release":
        raise ReleaseError("artifact matrix is not in release state")
    blocking_gaps = [
        entry.get("id")
        for entry in gaps.get("gaps", [])
        if isinstance(entry, dict) and entry.get("release_blocking") is True
    ]
    if blocking_gaps:
        raise ReleaseError(f"release qualification gaps remain open: {blocking_gaps}")
    if (
        not isinstance(release.get("source_date_epoch"), int)
        or release["source_date_epoch"] < 0
    ):
        raise ReleaseError("release evidence source date epoch is invalid")
    source = release.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        raise ReleaseError("release evidence is not bound to a committed, clean source")
    revision = source.get("revision")
    if (
        not isinstance(revision, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is None
    ):
        raise ReleaseError("release evidence source revision is invalid")
    if (
        not isinstance(source.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", source["tree_sha256"]) is None
    ):
        raise ReleaseError("release evidence source tree digest is invalid")

    build_reference = release.get("build")
    if not isinstance(build_reference, dict) or set(build_reference) != {
        "path",
        "sha256",
        "bytes",
    }:
        raise ReleaseError("release build-manifest reference is invalid")
    build_path = _referenced_file(dist, build_reference)
    build = load_json(build_path)
    if (
        not isinstance(build, dict)
        or set(build)
        != {
            "schema_version",
            "product_version",
            "context_abi",
            "source_date_epoch",
            "source",
            "artifacts",
        }
        or build.get("schema_version") != "cigar.release-build.v1"
        or build.get("product_version") != release.get("product_version")
        or build.get("context_abi") != release.get("context_abi")
        or build.get("source_date_epoch") != release.get("source_date_epoch")
        or build.get("source") != source
    ):
        raise ReleaseError("release build manifest is stale or has an unexpected shape")

    matrix_entries = {
        entry["id"]: entry
        for entry in matrix["artifacts"]
        if entry.get("required_for_release") is True
    }
    artifact_references = release.get("artifacts")
    if not isinstance(artifact_references, list):
        raise ReleaseError("release artifact references are invalid")
    typed_artifact_references: list[dict[str, Any]] = []
    artifact_ids: set[str] = set()
    for entry in artifact_references:
        if not isinstance(entry, dict):
            raise ReleaseError(
                "release artifact references contain a non-object record"
            )
        identifier = entry.get("id")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in artifact_ids
        ):
            raise ReleaseError(
                "release artifact references contain duplicate or invalid ids"
            )
        artifact_ids.add(identifier)
        typed_artifact_references.append(entry)
    if artifact_ids != set(matrix_entries):
        raise ReleaseError(
            f"release artifact matrix mismatch; missing={sorted(set(matrix_entries) - artifact_ids)}, extra={sorted(artifact_ids - set(matrix_entries))}"
        )
    artifact_references = typed_artifact_references
    artifacts: dict[str, Path] = {}
    artifact_paths: set[Path] = set()
    for reference in artifact_references:
        if (
            set(reference) != {"id", "path", "sha256", "bytes", "contract", "status"}
            or reference.get("status") != "passed"
        ):
            raise ReleaseError(
                "release artifact reference has an unexpected shape or status"
            )
        identifier = reference["id"]
        path = _referenced_file(dist, reference)
        if path.name != matrix_entries[identifier].get("filename"):
            raise ReleaseError(
                f"release artifact filename disagrees with the matrix: {identifier}"
            )
        if path.resolve() in artifact_paths:
            raise ReleaseError(
                f"multiple artifact ids reference the same payload: {path.relative_to(dist)}"
            )
        artifact_paths.add(path.resolve())
        expected_contract = f"packaging/{matrix_entries[identifier]['contract']}"
        if reference.get("contract") != expected_contract:
            raise ReleaseError(f"artifact contract reference mismatch: {identifier}")
        contract = resolve_beneath(
            root, f"packaging/{matrix_entries[identifier]['contract']}"
        )
        verification = verify_package(
            path,
            contract,
            matrix["product_version"],
            matrix["context_abi"],
            release["source_date_epoch"],
        )
        metadata = verification.get("metadata")
        if metadata is not None:
            if (
                metadata.get("artifact_id") != identifier
                or metadata.get("source") != source
            ):
                raise ReleaseError(
                    f"artifact release metadata is bound to a different source or artifact id: {identifier}"
                )
        artifacts[identifier] = path

    build_records = build.get("artifacts")
    if not isinstance(build_records, list) or any(
        not isinstance(record, dict) for record in build_records
    ):
        raise ReleaseError("release build manifest artifact records are invalid")
    normalized_build: dict[str, tuple[str, str, int, str]] = {}
    for record in build_records:
        if set(record) != {"id", "path", "sha256", "bytes", "contract"}:
            raise ReleaseError(
                "release build manifest artifact record has an unexpected shape"
            )
        identifier = record.get("id")
        path_value = record.get("path")
        digest = record.get("sha256")
        size = record.get("bytes")
        contract_value = record.get("contract")
        if (
            not isinstance(identifier, str)
            or identifier in normalized_build
            or not isinstance(path_value, str)
            or not isinstance(digest, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(contract_value, str)
        ):
            raise ReleaseError(
                "release build manifest artifact record has invalid fields"
            )
        normalized_build[identifier] = (path_value, digest, size, contract_value)
    expected_build = {
        reference["id"]: (
            reference["path"],
            reference["sha256"],
            reference["bytes"],
            reference["contract"],
        )
        for reference in artifact_references
    }
    if normalized_build != expected_build:
        raise ReleaseError(
            "release build manifest differs from assembled artifact references"
        )

    checksum_path = _find_unique(dist, "SHA256SUMS")
    checksums = _parse_checksums(checksum_path, dist)
    for reference in artifact_references:
        if checksums.get(reference["path"]) != reference["sha256"]:
            raise ReleaseError(
                f"artifact is missing from checksum manifest: {reference['path']}"
            )
    if set(checksums) != {reference["path"] for reference in artifact_references}:
        raise ReleaseError(
            "checksum manifest contains missing or unexpected artifact paths"
        )

    receipts: list[dict[str, Any]] = []
    receipt_paths: dict[Path, dict[str, Any]] = {}
    evidence_references = release.get("evidence")
    if not isinstance(evidence_references, list) or not evidence_references:
        raise ReleaseError("release evidence receipts are missing")
    for reference in evidence_references:
        expected_reference_keys = {
            "id",
            "category",
            "source_revision",
            "status",
            "artifact_ids",
            "metrics",
            "path",
            "sha256",
            "bytes",
        }
        if not isinstance(reference, dict) or set(reference) != expected_reference_keys:
            raise ReleaseError(
                "release qualification reference has an unexpected shape"
            )
        path = _referenced_file(dist, reference)
        if path.resolve() in artifact_paths:
            raise ReleaseError("qualification receipt path overlaps a release artifact")
        receipt = _validate_receipt(path, reference, dist, revision, artifact_ids)
        receipts.append(receipt)
        if path.resolve() in receipt_paths:
            raise ReleaseError(
                f"duplicate qualification receipt path: {path.relative_to(dist)}"
            )
        receipt_paths[path.resolve()] = receipt
    receipt_ids = [receipt["id"] for receipt in receipts]
    if len(set(receipt_ids)) != len(receipt_ids):
        raise ReleaseError("duplicate qualification receipt id")
    categories = {receipt["category"] for receipt in receipts}
    required_categories = set(requirements["required_evidence_categories"])
    if categories != required_categories:
        raise ReleaseError(
            f"release evidence categories mismatch; missing={sorted(required_categories - categories)}, extra={sorted(categories - required_categories)}"
        )
    _enforce_metric_gates(receipts, requirements)
    covered_artifacts: set[str] = set()
    for receipt in receipts:
        for identifier in receipt["artifact_ids"]:
            if not isinstance(identifier, str):
                raise ReleaseError(
                    "qualification receipt contains an invalid artifact id"
                )
            covered_artifacts.add(identifier)
    if covered_artifacts != artifact_ids:
        raise ReleaseError(
            f"release evidence does not cover every artifact: {sorted(artifact_ids - covered_artifacts)}"
        )
    _require_artifact_qualification(
        matrix_entries, artifact_ids, receipts, qualification_mapping
    )

    attachment_paths_by_category: dict[str, set[Path]] = {}
    for receipt in receipts:
        category_paths = attachment_paths_by_category.setdefault(
            receipt["category"], set()
        )
        for reference in receipt["attachments"]:
            attachment = resolve_beneath(dist, reference["path"]).resolve()
            if attachment in artifact_paths or attachment in receipt_paths:
                raise ReleaseError(
                    "qualification attachment overlaps an artifact or receipt"
                )
            category_paths.add(attachment)

    trust_policy_path = arguments.trust_policy.absolute()
    trusted = _load_trust_policy(
        trust_policy_path,
        openssl_path=reviewed_openssl,
        openssl_sha256=arguments.openssl_sha256,
    )
    purpose_by_payload: dict[Path, str] = {
        path.resolve(): "release-artifact" for path in artifacts.values()
    }
    checksum_path = _find_unique(dist, "SHA256SUMS")
    purpose_by_payload[checksum_path.resolve()] = "release-checksums"
    for basename in ("sbom.spdx.json", "sbom.cyclonedx.json", "sbom-artifacts.json"):
        purpose_by_payload[_find_unique(dist, basename).resolve()] = "release-sbom"
    provenance_path = _find_unique(dist, "provenance.json")
    purpose_by_payload[provenance_path.resolve()] = "release-provenance"
    for path, receipt in receipt_paths.items():
        category = receipt["category"]
        purpose_by_payload[path] = (
            f"release-{category}"
            if category in {"conformance", "benchmark"}
            else "release-qualification"
        )
    for category, paths in attachment_paths_by_category.items():
        desired = (
            f"release-{category}"
            if category in {"conformance", "benchmark"}
            else "release-qualification"
        )
        for path in paths:
            existing = purpose_by_payload.get(path)
            if (
                existing is not None
                and existing != desired
                and desired != "release-qualification"
            ):
                raise ReleaseError(
                    f"qualification attachment has conflicting signature purposes: {path.relative_to(dist)}"
                )
            if existing is None:
                purpose_by_payload[path] = desired
    purpose_by_payload[release_path.resolve()] = "release-evidence"
    signature_references = release.get("signatures")
    if not isinstance(signature_references, list) or not signature_references:
        raise ReleaseError("release signature references are missing")
    signed_paths: set[Path] = set()
    listed_envelopes: set[Path] = set()
    for reference in signature_references:
        if not isinstance(reference, dict) or set(reference) != {
            "path",
            "sha256",
            "bytes",
        }:
            raise ReleaseError("release signature reference has an unexpected shape")
        envelope_path = _referenced_file(dist, reference)
        if envelope_path in listed_envelopes:
            raise ReleaseError("duplicate release signature reference")
        listed_envelopes.add(envelope_path)
        envelope = load_json(envelope_path)
        payload = _signature_payload(dist, envelope).resolve()
        expected_purpose = purpose_by_payload.get(payload)
        if expected_purpose is None:
            raise ReleaseError(
                f"signature targets an unexpected release payload: {payload.relative_to(dist)}"
            )
        signed_paths.add(
            _verify_envelope(
                envelope_path,
                dist,
                trusted,
                expected_purpose,
                verification_time,
                openssl_path=reviewed_openssl,
                openssl_sha256=arguments.openssl_sha256,
            ).resolve()
        )
    release_signature = _find_unique(dist, "release-evidence.json.sig.json")
    signed_paths.add(
        _verify_envelope(
            release_signature,
            dist,
            trusted,
            "release-evidence",
            verification_time,
            openssl_path=reviewed_openssl,
            openssl_sha256=arguments.openssl_sha256,
        ).resolve()
    )
    for artifact in artifacts.values():
        if artifact.resolve() not in signed_paths:
            raise ReleaseError(f"release artifact is not signed: {artifact.name}")
    for basename in requirements.get("required_signed_basenames", []):
        required_path = _find_unique(dist, basename)
        if required_path.resolve() not in signed_paths:
            raise ReleaseError(f"required release payload is not signed: {basename}")
    for category in requirements.get("required_signed_evidence_categories", []):
        category_paths = {
            path
            for path, receipt in receipt_paths.items()
            if receipt["category"] == category
        } | attachment_paths_by_category.get(category, set())
        if not category_paths or not category_paths.issubset(signed_paths):
            raise ReleaseError(f"required {category} evidence is not directly signed")
    discovered_envelopes = {
        path.resolve() for path in dist.rglob("*.sig.json") if path.is_file()
    }
    expected_envelopes = {path.resolve() for path in listed_envelopes} | {
        release_signature.resolve()
    }
    if discovered_envelopes != expected_envelopes:
        raise ReleaseError("signature envelope set differs from release evidence")

    sbom_paths = _validate_sboms(dist, artifacts, release["product_version"])
    _validate_provenance(
        provenance_path, artifacts, root, revision, release["source_date_epoch"]
    )

    expected_files = (
        artifact_paths
        | set(receipt_paths)
        | {path for paths in attachment_paths_by_category.values() for path in paths}
        | expected_envelopes
        | sbom_paths
        | {
            release_path.resolve(),
            build_path.resolve(),
            checksum_path.resolve(),
            provenance_path.resolve(),
        }
    )
    actual_files = {path.resolve() for path in dist.rglob("*") if path.is_file()}
    if actual_files != expected_files:
        missing = sorted(
            str(path.relative_to(dist)) for path in expected_files - actual_files
        )
        extra = sorted(
            str(path.relative_to(dist)) for path in actual_files - expected_files
        )
        raise ReleaseError(
            f"release directory inventory mismatch; missing={missing}, extra={extra}"
        )

    report = {
        "schema_version": "cigar.release-verification.v1",
        "status": "passed",
        "product_version": release["product_version"],
        "context_abi": release["context_abi"],
        "source_revision": revision,
        "artifact_count": len(artifacts),
        "evidence_count": len(receipts),
        "signature_count": len(expected_envelopes),
        "trusted_key_ids": sorted(trusted),
        "trust_policy_sha256": sha256_file(trust_policy_path),
        "reviewed_openssl_sha256": arguments.openssl_sha256,
        "verification_time": verification_time,
    }
    if report_output is not None:
        report_output.publish(report)
    print(
        f"offline release verification passed for {len(artifacts)} artifacts and {len(receipts)} evidence receipts"
    )
    return 0


def main() -> int:
    arguments = parse_arguments()
    dist = arguments.directory.resolve()
    if not dist.is_dir():
        raise ReleaseError("release directory does not exist")
    report_output = _ReportOutput.open(
        arguments,
        repository_root=arguments.root.resolve(),
        dist=dist,
    )
    try:
        return _run_verification(arguments, report_output)
    finally:
        if report_output is not None:
            report_output.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, ReleaseError) as error:
        raise SystemExit(f"offline release verification failed: {error}") from error
