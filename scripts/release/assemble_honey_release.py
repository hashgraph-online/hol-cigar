#!/usr/bin/env python3
"""Assemble exact Honey developer-preview artifacts without rebuilding them.

The assembler consumes owner-private workspaces produced by the selected Honey
artifact producers.  It validates every receipt, package contract, source
binding, and authority digest before copying bytes into a new owner-private
candidate directory.  It deliberately does not sign, publish, or execute an
artifact.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unicodedata
from typing import Any, Iterable, Mapping

from evidence_workspace import (
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
)
from verify_package import verify as verify_package


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRODUCT_PATH = "packaging/product-version.v1.json"
PROFILE_PATH = "packaging/honey/capability-profile.v1.json"
MATRIX_PATH = "packaging/honey/artifact-matrix.v1.json"
REQUIREMENTS_PATH = "packaging/honey/release-requirements.v1.json"
MANIFEST_NAME = "honey-release-manifest.json"
CHECKSUM_NAME = "SHA256SUMS"
MANIFEST_SCHEMA = "cigar.honey.release-manifest.v1"
EXPECTED_VERSION = "0.9.0-honey.1"
EXPECTED_ABI = "cigar.context.v1"
EXPECTED_CHANNEL = "honey"
EXPECTED_STATE = "developer-preview"
EXPECTED_TARGET = "aarch64-apple-darwin"
EXPECTED_ARTIFACT_COUNT = 13
MAX_INPUT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")

COMMON_HONEY_AUTHORITY_PATHS = (
    PRODUCT_PATH,
    PROFILE_PATH,
    MATRIX_PATH,
    REQUIREMENTS_PATH,
)
PORTABLE_AUTHORITY_PATHS = (
    *COMMON_HONEY_AUTHORITY_PATHS,
    "packaging/honey/local-archives.v1.json",
    "packaging/honey/contracts/source-archive.v1.json",
    "packaging/honey/contracts/docs-archive.v1.json",
    "packaging/honey/contracts/schemas-conformance.v1.json",
)
RECEIPT_AUTHORITY_PATHS: dict[str, tuple[str, ...]] = {
    "source": PORTABLE_AUTHORITY_PATHS,
    "docs": PORTABLE_AUTHORITY_PATHS,
    "schemas-conformance": PORTABLE_AUTHORITY_PATHS,
    "macos-runtime-aarch64": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/honey/local-archives.v1.json",
        "packaging/contracts/macos-runtime-archive.v1.json",
        "adapters/claude-code/package-manifest.json",
    ),
    "typescript-sdk": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/contracts/npm-package.v1.json",
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "sdk/typescript/package.json",
        "sdk/typescript/release.json",
    ),
    "python-sdk-wheel": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/contracts/python-sdist.v1.json",
        "packaging/contracts/python-wheel.v1.json",
        "sdk/python/pyproject.toml",
        "sdk/python/uv.lock",
        "sdk/python/src/cigar_sdk/release.json",
    ),
    "python-sdk-sdist": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/contracts/python-sdist.v1.json",
        "packaging/contracts/python-wheel.v1.json",
        "sdk/python/pyproject.toml",
        "sdk/python/uv.lock",
        "sdk/python/src/cigar_sdk/release.json",
    ),
    "rust-sdk-local-registry": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/honey/contracts/rust-sdk-local-registry.v1.json",
        "Cargo.toml",
        "Cargo.lock",
        "sdk/rust/Cargo.toml",
        "sdk/rust/README.md",
        "sdk/rust/release.json",
    ),
    "claude-code-plugin": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/contracts/plugin-archive.v1.json",
        "packaging/contracts/macos-runtime-archive.v1.json",
        "adapters/claude-code/package-manifest.json",
    ),
    "honey-demos": (
        *COMMON_HONEY_AUTHORITY_PATHS,
        "packaging/honey/contracts/demos-archive.v1.json",
    ),
}


class HoneyAssemblyError(ReleaseError):
    """The Honey inputs cannot produce an honest developer preview."""


@dataclass(frozen=True)
class ArtifactSpec:
    identifier: str
    kind: str
    filename: str
    contract: str | None
    workspace: str
    generated: bool
    receipt_required: bool
    receipt_filename: str | None
    receipt_schema: str | None
    sha256_required: bool


@dataclass(frozen=True)
class Configuration:
    root: Path
    version: str
    context_abi: str
    profile_id: str
    artifacts: tuple[ArtifactSpec, ...]
    profile_digest: str
    matrix_digest: str
    requirements_digest: str
    internal_input_ids: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryState:
    revision: str
    clean: bool
    status_sha256: str


@dataclass(frozen=True)
class ValidatedArtifact:
    spec: ArtifactSpec
    payload: bytes
    source: Mapping[str, Any]
    receipt_name: str | None
    receipt_schema: str | None
    receipt_sha256: str | None
    receipt_bytes: int | None

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.payload)

    @property
    def byte_count(self) -> int:
        return len(self.payload)


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _safe_basename(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise HoneyAssemblyError(f"{label} must be a portable basename")
    if safe_relative_path(value) != value:
        raise HoneyAssemblyError(f"{label} is not a safe relative name")
    return value


def _canonical_document(payload: bytes, label: str) -> dict[str, Any]:
    document = load_json_bytes(payload, label)
    if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
        raise HoneyAssemblyError(f"{label} is not a canonical JSON object")
    return document


def _repository_state(root: Path) -> RepositoryState:
    revision = run_bounded(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        timeout=60,
        max_stdout=1024,
        max_stderr=1024 * 1024,
    )
    if revision.returncode != 0:
        raise HoneyAssemblyError("Honey assembly requires an existing source commit")
    revision_text = revision.stdout.decode("ascii", errors="strict").strip()
    if _REVISION.fullmatch(revision_text) is None:
        raise HoneyAssemblyError("repository HEAD is not a canonical revision")
    status = run_bounded(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        timeout=60,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if status.returncode != 0:
        raise HoneyAssemblyError("cannot inspect repository status")
    return RepositoryState(
        revision=revision_text,
        clean=not bool(status.stdout.strip()),
        status_sha256=sha256_bytes(status.stdout),
    )


def _load_configuration(root: Path) -> Configuration:
    root = root.resolve(strict=True)
    product = load_json(root / PRODUCT_PATH)
    profile = load_json(root / PROFILE_PATH)
    matrix = load_json(root / MATRIX_PATH)
    requirements = load_json(root / REQUIREMENTS_PATH)
    if (
        not isinstance(product, dict)
        or product.get("version") != EXPECTED_VERSION
        or product.get("target_release_version") != "0.9.0"
        or product.get("context_abi") != EXPECTED_ABI
        or product.get("release_state") != EXPECTED_STATE
        or product.get("channel") != EXPECTED_CHANNEL
        or product.get("prerelease") is not True
        or product.get("published") is not False
        or product.get("supported") is not False
        or product.get("tag") != f"v{EXPECTED_VERSION}"
    ):
        raise HoneyAssemblyError("product authority is not the bounded Honey identity")
    profile_identity = profile.get("identity") if isinstance(profile, dict) else None
    if (
        not isinstance(profile, dict)
        or not isinstance(profile.get("profile_id"), str)
        or not isinstance(profile_identity, dict)
        or profile_identity.get("product_version") != EXPECTED_VERSION
        or profile_identity.get("context_abi") != EXPECTED_ABI
        or profile_identity.get("release_state") != EXPECTED_STATE
        or profile_identity.get("channel") != EXPECTED_CHANNEL
        or profile_identity.get("prerelease") is not True
        or profile_identity.get("published") is not False
        or profile_identity.get("supported") is not False
        or profile_identity.get("production_qualified") is not False
    ):
        raise HoneyAssemblyError("Honey capability profile is malformed")
    profile_id = profile["profile_id"]
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.honey.artifact-matrix.v1"
        or matrix.get("profile_id") != profile_id
        or matrix.get("product_version") != EXPECTED_VERSION
        or matrix.get("context_abi") != EXPECTED_ABI
        or matrix.get("release_state") != EXPECTED_STATE
        or matrix.get("fail_closed") is not True
        or not isinstance(matrix.get("artifacts"), list)
        or len(matrix["artifacts"]) != EXPECTED_ARTIFACT_COUNT
    ):
        raise HoneyAssemblyError("Honey artifact matrix is malformed or stale")
    if (
        not isinstance(requirements, dict)
        or requirements.get("schema_version") != "cigar.honey.release-requirements.v1"
        or requirements.get("profile_id") != profile_id
        or requirements.get("evidence_class") != EXPECTED_STATE
        or requirements.get("fail_closed") is not True
        or requirements.get("machine_claims")
        != {
            "prerelease": True,
            "production_qualified": False,
            "supported": False,
        }
    ):
        raise HoneyAssemblyError("Honey release requirements are malformed")

    specs: list[ArtifactSpec] = []
    identifiers: set[str] = set()
    filenames: set[str] = set()
    filename_aliases: set[str] = set()
    for index, row in enumerate(matrix["artifacts"]):
        if not isinstance(row, dict):
            raise HoneyAssemblyError(f"artifact row {index} is not an object")
        identifier = row.get("id")
        filename = _safe_basename(row.get("filename"), f"artifact row {index} filename")
        portable = _portable_key(filename)
        if (
            not isinstance(identifier, str)
            or _IDENTIFIER.fullmatch(identifier) is None
            or identifier in identifiers
            or filename in filenames
            or portable in filename_aliases
            or row.get("public_attachment") is not True
            or row.get("required") is not True
        ):
            raise HoneyAssemblyError(
                f"artifact row {index} is duplicated or unselected"
            )
        kind = row.get("kind")
        if not isinstance(kind, str) or _IDENTIFIER.fullmatch(kind) is None:
            raise HoneyAssemblyError(f"artifact {identifier} has an invalid kind")
        generated = row.get("generated_by_assembler") is True
        workspace = row.get("workspace")
        if generated:
            workspace = "assembly"
        elif not isinstance(workspace, str) or _IDENTIFIER.fullmatch(workspace) is None:
            raise HoneyAssemblyError(f"artifact {identifier} has no bounded workspace")
        contract_value = row.get("contract")
        contract: str | None
        if contract_value is None:
            contract = None
        elif (
            isinstance(contract_value, str)
            and safe_relative_path(contract_value) == contract_value
        ):
            contract = contract_value
            contract_path = root / contract
            if contract_path.is_symlink() or not contract_path.is_file():
                raise HoneyAssemblyError(
                    f"artifact contract is unavailable: {contract}"
                )
        else:
            raise HoneyAssemblyError(f"artifact {identifier} has an unsafe contract")
        receipt = row.get("receipt")
        if not isinstance(receipt, dict):
            raise HoneyAssemblyError(
                f"artifact {identifier} receipt policy is malformed"
            )
        receipt_required = receipt.get("required") is True
        receipt_filename = receipt.get("filename")
        receipt_schema = receipt.get("schema_version")
        if receipt_required:
            receipt_filename = _safe_basename(
                receipt_filename, f"artifact {identifier} receipt"
            )
            if not isinstance(receipt_schema, str) or not receipt_schema:
                raise HoneyAssemblyError(
                    f"artifact {identifier} receipt schema is absent"
                )
        elif receipt_filename is not None or receipt_schema is not None:
            raise HoneyAssemblyError(
                f"artifact {identifier} optional receipt must be null"
            )
        if generated and (contract is not None or receipt_required):
            raise HoneyAssemblyError(
                f"assembler-generated artifact {identifier} cannot have external inputs"
            )
        sha256_required = row.get("sha256_required") is True
        specs.append(
            ArtifactSpec(
                identifier=identifier,
                kind=kind,
                filename=filename,
                contract=contract,
                workspace=workspace,
                generated=generated,
                receipt_required=receipt_required,
                receipt_filename=receipt_filename,
                receipt_schema=receipt_schema,
                sha256_required=sha256_required,
            )
        )
        identifiers.add(identifier)
        filenames.add(filename)
        filename_aliases.add(portable)
    if {spec.filename for spec in specs if spec.generated} != {
        MANIFEST_NAME,
        CHECKSUM_NAME,
    }:
        raise HoneyAssemblyError("Honey assembler-generated inventory is not exact")

    internal_input_ids: list[str] = []
    for row in matrix.get("internal_inputs", []):
        if (
            not isinstance(row, dict)
            or row.get("required") is not True
            or row.get("public_attachment") is not False
            or not isinstance(row.get("evidence_class"), str)
            or _IDENTIFIER.fullmatch(row["evidence_class"]) is None
        ):
            raise HoneyAssemblyError("Honey internal input row is malformed")
        identifier = row.get("id")
        if (
            not isinstance(identifier, str)
            or _IDENTIFIER.fullmatch(identifier) is None
            or identifier in internal_input_ids
        ):
            raise HoneyAssemblyError("Honey internal input identifier is invalid")
        internal_input_ids.append(identifier)

    return Configuration(
        root=root,
        version=EXPECTED_VERSION,
        context_abi=EXPECTED_ABI,
        profile_id=profile_id,
        artifacts=tuple(specs),
        profile_digest=sha256_file(root / PROFILE_PATH),
        matrix_digest=sha256_file(root / MATRIX_PATH),
        requirements_digest=sha256_file(root / REQUIREMENTS_PATH),
        internal_input_ids=tuple(internal_input_ids),
    )


def _parse_workspace(value: str) -> tuple[str, Path]:
    key, separator, raw_path = value.partition("=")
    if separator != "=" or _IDENTIFIER.fullmatch(key) is None or not raw_path:
        raise argparse.ArgumentTypeError("workspace must have key=/absolute/path form")
    path = Path(raw_path)
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise argparse.ArgumentTypeError(
            "workspace path must be absolute and canonical"
        )
    return key, path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--workspace",
        action="append",
        type=_parse_workspace,
        default=[],
        metavar="KEY=/ABSOLUTE/PATH",
    )
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--source-date-epoch")
    return parser.parse_args()


def _external_workspace(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise HoneyAssemblyError(f"{label} must be an absolute canonical path")
    try:
        inside = os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(
            root
        )
    except ValueError:
        inside = False
    if inside:
        raise HoneyAssemblyError(f"{label} must be outside the source repository")
    return path


def _source_from_receipt(
    receipt: Mapping[str, Any], state: RepositoryState
) -> Mapping[str, Any]:
    source = receipt.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or source.get("revision") != state.revision
        or _SHA256.fullmatch(str(source.get("tree_sha256"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        raise HoneyAssemblyError("producer receipt source is stale or unclean")
    return source


def _artifact_references(receipt: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    archive = receipt.get("archive")
    if isinstance(archive, dict):
        yield archive
    artifacts = receipt.get("artifacts")
    if isinstance(artifacts, dict):
        for value in artifacts.values():
            if isinstance(value, dict):
                yield value
    elif isinstance(artifacts, list):
        for value in artifacts:
            if isinstance(value, dict):
                yield value


def _required_receipt_authority(spec: ArtifactSpec) -> tuple[str, ...]:
    required = RECEIPT_AUTHORITY_PATHS.get(spec.identifier)
    if required is None or spec.contract not in required:
        raise HoneyAssemblyError(
            f"{spec.identifier} has no exact Honey receipt authority policy"
        )
    if len(required) != len(set(required)):
        raise HoneyAssemblyError(
            f"{spec.identifier} Honey receipt authority policy is duplicated"
        )
    return required


def _validate_receipt_authority(
    value: object,
    required: tuple[str, ...],
    configuration: Configuration,
    label: str,
) -> None:
    if not isinstance(value, dict) or set(value) != set(required):
        raise HoneyAssemblyError(f"{label} authority inventory is not exact")
    for relative in required:
        binding = value.get(relative)
        path = configuration.root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise HoneyAssemblyError(
                f"{label} authority is unavailable: {relative}"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise HoneyAssemblyError(
                f"{label} authority is not a regular file: {relative}"
            )
        if (
            not isinstance(binding, dict)
            or set(binding) != {"sha256", "bytes"}
            or binding.get("sha256") != sha256_file(path)
            or binding.get("bytes") != metadata.st_size
        ):
            raise HoneyAssemblyError(f"{label} authority changed: {relative}")


def _validate_receipt(
    payload: bytes,
    spec: ArtifactSpec,
    artifact: bytes,
    configuration: Configuration,
    state: RepositoryState,
    epoch: int,
) -> tuple[Mapping[str, Any], str]:
    receipt = _canonical_document(payload, f"{spec.identifier} receipt")
    if (
        receipt.get("schema_version") != spec.receipt_schema
        or receipt.get("product_version") != configuration.version
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("source_date_epoch") != epoch
        or receipt.get("status") not in {"built-unqualified", "honey-built-unqualified"}
    ):
        raise HoneyAssemblyError(f"{spec.identifier} receipt identity is stale")
    source = _source_from_receipt(receipt, state)
    matches = []
    for reference in _artifact_references(receipt):
        path = reference.get("path")
        if path == spec.filename:
            matches.append(reference)
    if len(matches) != 1:
        raise HoneyAssemblyError(
            f"{spec.identifier} receipt does not bind its exact artifact once"
        )
    reference = matches[0]
    if reference.get("sha256") != sha256_bytes(artifact) or reference.get(
        "bytes"
    ) != len(artifact):
        raise HoneyAssemblyError(f"{spec.identifier} receipt artifact binding changed")
    _validate_receipt_authority(
        receipt.get("authority"),
        _required_receipt_authority(spec),
        configuration,
        f"{spec.identifier} receipt",
    )
    return source, receipt["schema_version"]


def _parse_portable_manifest(
    payload: bytes,
    specs: tuple[ArtifactSpec, ...],
    artifacts: Mapping[str, bytes],
    configuration: Configuration,
    state: RepositoryState,
    epoch: int,
) -> Mapping[str, Any]:
    receipt = _canonical_document(payload, "portable build manifest")
    if (
        receipt.get("schema_version")
        not in {
            "cigar.local-archive-build.v1",
            "cigar.honey-portable-build.v1",
        }
        or receipt.get("product_version") != configuration.version
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("source_date_epoch") != epoch
        or not isinstance(receipt.get("artifacts"), list)
    ):
        raise HoneyAssemblyError("portable build manifest identity is stale")
    source = _source_from_receipt(receipt, state)
    expected = {
        (
            spec.identifier,
            spec.filename,
            sha256_bytes(artifacts[spec.identifier]),
            len(artifacts[spec.identifier]),
        )
        for spec in specs
    }
    observed = set()
    for row in receipt["artifacts"]:
        if not isinstance(row, dict):
            raise HoneyAssemblyError("portable artifact receipt row is malformed")
        observed.add(
            (row.get("id"), row.get("path"), row.get("sha256"), row.get("bytes"))
        )
    if observed != expected:
        raise HoneyAssemblyError(
            "portable build manifest artifact inventory is not exact"
        )
    required_sets = {_required_receipt_authority(spec) for spec in specs}
    if required_sets != {PORTABLE_AUTHORITY_PATHS}:
        raise HoneyAssemblyError("portable receipt authority policy is not exact")
    _validate_receipt_authority(
        receipt.get("authority"),
        PORTABLE_AUTHORITY_PATHS,
        configuration,
        "portable build manifest",
    )
    return source


def _publish_payload(
    workspace: EvidenceWorkspace, relative: str, payload: bytes
) -> None:
    with tempfile.TemporaryDirectory(prefix="cigar-honey-assembly-copy-") as raw:
        staging = Path(raw).resolve(strict=True)
        # Assembly staging contains unpublished release payloads and stays owner-private.
        os.chmod(staging, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        source = staging / "payload"
        descriptor = os.open(
            source,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise HoneyAssemblyError("short write while staging Honey artifact")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        workspace.attach_file(
            source,
            relative,
            read_only=True,
            expected_sha256=sha256_bytes(payload),
            expected_bytes=len(payload),
        )


def _release_notes(root: Path, spec: ArtifactSpec) -> bytes:
    path = root / spec.filename
    if path.is_symlink() or not path.is_file():
        raise HoneyAssemblyError("Honey release notes are missing")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_JSON_BYTES
    ):
        raise HoneyAssemblyError("Honey release notes have unsafe metadata")
    payload = path.read_bytes()
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise HoneyAssemblyError("Honey release notes are not UTF-8") from error
    if (
        not text.endswith("\n")
        or "\r" in text
        or EXPECTED_VERSION not in text
        or "developer preview" not in text.casefold()
    ):
        raise HoneyAssemblyError(
            "Honey release notes omit required identity or limitation"
        )
    return payload


def _checksum_payload(payloads: Mapping[str, bytes], manifest: bytes) -> bytes:
    records = {**payloads, MANIFEST_NAME: manifest}
    return "".join(
        f"{sha256_bytes(payload)}  {name}\n"
        for name, payload in sorted(
            records.items(), key=lambda item: item[0].encode("utf-8")
        )
    ).encode("ascii")


def assemble(arguments: argparse.Namespace) -> dict[str, Any]:
    configuration = _load_configuration(arguments.root)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    state = _repository_state(configuration.root)
    if not state.clean:
        raise HoneyAssemblyError(
            "Honey assembly requires a clean committed source tree"
        )
    supplied: dict[str, Path] = {}
    for key, path in arguments.workspace:
        if key in supplied:
            raise HoneyAssemblyError(f"duplicate producer workspace: {key}")
        supplied[key] = _external_workspace(
            path, configuration.root, f"{key} workspace"
        )
    required_workspaces = {
        spec.workspace
        for spec in configuration.artifacts
        if not spec.generated and spec.workspace not in {"source-metadata", "assembly"}
    }
    if set(supplied) != required_workspaces:
        raise HoneyAssemblyError(
            f"producer workspace mismatch: required={sorted(required_workspaces)} supplied={sorted(supplied)}"
        )

    specs_by_workspace = {
        key: tuple(spec for spec in configuration.artifacts if spec.workspace == key)
        for key in required_workspaces
    }
    extras_by_workspace: dict[str, set[str]] = {
        key: ({"SHA256SUMS"} if key == "portable" else set())
        for key in required_workspaces
    }

    payloads: dict[str, bytes] = {}
    validated: dict[str, ValidatedArtifact] = {}
    common_revision: str | None = None
    source_identity: Mapping[str, Any] | None = None
    workspaces: list[EvidenceWorkspace] = []
    try:
        for key in sorted(required_workspaces):
            specs = specs_by_workspace[key]
            inventory = {spec.filename for spec in specs}
            inventory.update(
                spec.receipt_filename
                for spec in specs
                if spec.receipt_filename is not None
            )
            inventory.update(extras_by_workspace[key])
            workspace = EvidenceWorkspace.create(
                supplied[key],
                repository_root=configuration.root,
                limits=EvidenceLimits(
                    max_files=max(16, len(inventory) + 4),
                    max_directories=4,
                    max_file_bytes=MAX_ARTIFACT_BYTES,
                    max_total_bytes=MAX_INPUT_TOTAL_BYTES,
                    max_json_bytes=MAX_JSON_BYTES,
                    max_path_depth=2,
                ),
            )
            workspaces.append(workspace)
            snapshot = workspace.read_files(inventory, strict_read_only=True)
            workspace_payloads = {
                spec.identifier: snapshot[spec.filename] for spec in specs
            }
            portable_receipt: Mapping[str, Any] | None = None
            portable_receipt_name = next(
                (
                    spec.receipt_filename
                    for spec in specs
                    if spec.receipt_schema == "cigar.local-archive-build.v1"
                ),
                None,
            )
            if portable_receipt_name is not None:
                portable_receipt = _parse_portable_manifest(
                    snapshot[portable_receipt_name],
                    specs,
                    workspace_payloads,
                    configuration,
                    state,
                    epoch,
                )
            for spec in specs:
                artifact = workspace_payloads[spec.identifier]
                if len(artifact) <= 0 or len(artifact) > MAX_ARTIFACT_BYTES:
                    raise HoneyAssemblyError(
                        f"artifact size is invalid: {spec.identifier}"
                    )
                receipt_payload: bytes | None = None
                receipt_schema: str | None = None
                source: Mapping[str, Any]
                if spec.receipt_required:
                    assert spec.receipt_filename is not None
                    receipt_payload = snapshot[spec.receipt_filename]
                    if (
                        portable_receipt is not None
                        and spec.receipt_filename == portable_receipt_name
                    ):
                        source = portable_receipt
                        receipt_schema = "cigar.local-archive-build.v1"
                    else:
                        source, receipt_schema = _validate_receipt(
                            receipt_payload,
                            spec,
                            artifact,
                            configuration,
                            state,
                            epoch,
                        )
                else:
                    raise HoneyAssemblyError(
                        f"non-generated producer artifact lacks a receipt: {spec.identifier}"
                    )
                if common_revision is None:
                    common_revision = str(source["revision"])
                elif source["revision"] != common_revision:
                    raise HoneyAssemblyError(
                        "producer receipts do not share one source revision"
                    )
                if spec.identifier == "source" or source_identity is None:
                    source_identity = source
                if spec.contract is not None:
                    with tempfile.TemporaryDirectory(
                        prefix="cigar-honey-package-"
                    ) as raw:
                        package_path = Path(raw) / spec.filename
                        package_path.write_bytes(artifact)
                        verification = verify_package(
                            package_path,
                            configuration.root / spec.contract,
                            configuration.version,
                            configuration.context_abi,
                            epoch,
                        )
                    if verification.get("status") != "passed":
                        raise HoneyAssemblyError(
                            f"package verification failed: {spec.identifier}"
                        )
                payloads[spec.filename] = artifact
                validated[spec.identifier] = ValidatedArtifact(
                    spec=spec,
                    payload=artifact,
                    source=source,
                    receipt_name=spec.receipt_filename,
                    receipt_schema=receipt_schema,
                    receipt_sha256=(
                        sha256_bytes(receipt_payload) if receipt_payload else None
                    ),
                    receipt_bytes=(len(receipt_payload) if receipt_payload else None),
                )
        for spec in configuration.artifacts:
            if spec.workspace != "source-metadata" or spec.generated:
                continue
            payload = _release_notes(configuration.root, spec)
            payloads[spec.filename] = payload
            assert source_identity is not None
            validated[spec.identifier] = ValidatedArtifact(
                spec=spec,
                payload=payload,
                source=source_identity,
                receipt_name=None,
                receipt_schema=None,
                receipt_sha256=None,
                receipt_bytes=None,
            )
    finally:
        for workspace in workspaces:
            workspace.close()

    expected_payload_specs = tuple(
        spec for spec in configuration.artifacts if not spec.generated
    )
    if set(validated) != {spec.identifier for spec in expected_payload_specs}:
        raise HoneyAssemblyError("validated Honey payload inventory is incomplete")
    if source_identity is None or common_revision != state.revision:
        raise HoneyAssemblyError("Honey payloads have no common source identity")
    if _repository_state(configuration.root) != state:
        raise HoneyAssemblyError("repository state changed during Honey validation")

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "profile_id": configuration.profile_id,
        "channel": EXPECTED_CHANNEL,
        "release_state": EXPECTED_STATE,
        "target": EXPECTED_TARGET,
        "source_date_epoch": epoch,
        "source": dict(source_identity),
        "authority": {
            PROFILE_PATH: configuration.profile_digest,
            MATRIX_PATH: configuration.matrix_digest,
            REQUIREMENTS_PATH: configuration.requirements_digest,
        },
        "artifacts": [
            {
                "id": spec.identifier,
                "kind": spec.kind,
                "path": spec.filename,
                "sha256": validated[spec.identifier].sha256,
                "bytes": validated[spec.identifier].byte_count,
                "contract": spec.contract,
                "producer_receipt": (
                    {
                        "path": validated[spec.identifier].receipt_name,
                        "schema_version": validated[spec.identifier].receipt_schema,
                        "sha256": validated[spec.identifier].receipt_sha256,
                        "bytes": validated[spec.identifier].receipt_bytes,
                    }
                    if validated[spec.identifier].receipt_name is not None
                    else None
                ),
                "status": "honey-built-unqualified",
            }
            for spec in expected_payload_specs
        ],
        "evidence": {
            "status": "not-evaluated",
            "public_attachment": False,
            "required_internal_inputs": [
                {"id": identifier, "status": "not-evaluated"}
                for identifier in configuration.internal_input_ids
            ],
        },
        "claims": {
            "developer_preview": True,
            "prerelease": True,
            "published": False,
            "supported": False,
            "production_qualified": False,
            "signed": False,
            "notarized": False,
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    checksum_payload = _checksum_payload(payloads, manifest_payload)
    output = _external_workspace(
        arguments.evidence_dir, configuration.root, "assembly output"
    )
    output_workspace = EvidenceWorkspace.create(
        output,
        repository_root=configuration.root,
        limits=EvidenceLimits(
            max_files=EXPECTED_ARTIFACT_COUNT + 4,
            max_directories=2,
            max_file_bytes=MAX_ARTIFACT_BYTES,
            max_total_bytes=MAX_OUTPUT_TOTAL_BYTES,
            max_json_bytes=MAX_JSON_BYTES,
            max_path_depth=2,
        ),
    )
    try:
        output_workspace.read_files(set(), strict_read_only=False)
        for filename, payload in sorted(
            payloads.items(), key=lambda item: item[0].encode("utf-8")
        ):
            _publish_payload(output_workspace, filename, payload)
        output_workspace.write_json(MANIFEST_NAME, manifest)
        _publish_payload(output_workspace, CHECKSUM_NAME, checksum_payload)
        output_workspace.read_files(
            {spec.filename for spec in configuration.artifacts}, strict_read_only=True
        )
    finally:
        output_workspace.close()
    if _repository_state(configuration.root) != state:
        raise HoneyAssemblyError("repository changed while publishing Honey candidate")
    return manifest


def main() -> int:
    manifest = assemble(parse_arguments())
    print(canonical_json_bytes(manifest).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        HoneyAssemblyError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"Honey assembly failed: {error}") from error
