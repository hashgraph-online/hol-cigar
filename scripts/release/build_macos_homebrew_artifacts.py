#!/usr/bin/env python3
"""Build development-only Apple-silicon Homebrew tap and bottle artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from typing import Any

from build_macos_aarch64_archive import (
    AUTHORITY_PATHS as NATIVE_AUTHORITY_PATHS,
    MACOS_NO_EGRESS_ENFORCEMENT,
    MACOS_NO_EGRESS_POLICY,
    MACOS_SANDBOX_EXEC,
    MAX_ARCHIVE_BYTES,
    RUNTIME_PROFILE as NATIVE_RUNTIME_PROFILE,
    _read_stable_file,
    _require_host,
    _validate_macho_arm64,
)
from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    require_source_date_epoch,
    safe_relative_path,
    sha256_bytes,
)
from verify_package import _validate_contract, verify as verify_package


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NATIVE_ARTIFACT_ID = "cli-daemon-macos-aarch64"
FORMULA_ARTIFACT_ID = "macos-homebrew-formula-arm64"
BOTTLE_ARTIFACT_ID = "macos-installer-arm64"
TARGET_TRIPLE = "aarch64-apple-darwin"
BOTTLE_TAG = "arm64_sequoia"
BOTTLE_REBUILD = 0
BOTTLE_CELLAR = "any_skip_relocation"
BOTTLE_MACOS_VERSION = "15.6"
DEVELOPMENT_DOWNLOAD_ROOT = "https://downloads.cigar.invalid/development"
BUILD_RECEIPT = "macos-homebrew-development-build.json"
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_FORMULA_BYTES = 256 * 1024
HOMEBREW_RECEIPT_COMPATIBILITY_VERSION = "6.0.8"

AUTHORITY_PATHS = (
    "LICENSE",
    "NOTICE",
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/local-archives.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    "packaging/contracts/homebrew-bottle.v1.json",
    "packaging/contracts/homebrew-tap.v1.json",
    "adapters/claude-code/package-manifest.json",
    "scripts/release/build_macos_aarch64_archive.py",
    "scripts/release/build_macos_homebrew_artifacts.py",
    "scripts/release/verify_macos_homebrew_artifacts.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
)


@dataclass(frozen=True)
class Entry:
    path: str
    payload: bytes
    mode: int


@dataclass(frozen=True)
class Configuration:
    root: Path
    version: str
    context_abi: str
    native_filename: str
    bottle_filename: str
    tap_filename: str
    bottle_contract: Path
    tap_contract: Path
    authority: dict[str, dict[str, object]]
    license_payload: bytes
    notice_payload: bytes


def _validate_bottle_host(host: dict[str, str]) -> dict[str, str]:
    """Require the exact native host represented by the deterministic bottle."""

    expected = {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": BOTTLE_MACOS_VERSION,
    }
    if host != expected:
        raise ReleaseError(
            "Homebrew bottle construction requires the pinned Apple-silicon "
            f"macOS {BOTTLE_MACOS_VERSION} host; observed {host}"
        )
    return host


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--native-archive", type=Path, required=True)
    parser.add_argument("--native-build-receipt", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external empty output workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--source-date-epoch")
    return parser.parse_args()


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment and Path(argument) != Path(environment):
        raise ReleaseError(
            "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide one location"
        )
    raw = argument if argument is not None else environment
    if raw is None or os.fspath(raw) == "":
        raise ReleaseError("--evidence-dir or CIGAR_EVIDENCE_DIR is required")
    selected = Path(raw)
    if not selected.is_absolute() or Path(os.path.normpath(selected)) != selected:
        raise ReleaseError("evidence directory must be an absolute canonical path")
    return selected


def _absolute_input(path: Path, label: str, root: Path, evidence: Path) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise ReleaseError(f"{label} must be an absolute canonical path")
    for forbidden, boundary in ((root, "repository"), (evidence, "output workspace")):
        try:
            inside = os.path.commonpath(
                (os.fspath(path), os.fspath(forbidden))
            ) == os.fspath(forbidden)
        except ValueError:
            inside = False
        if inside:
            raise ReleaseError(f"{label} must be outside the {boundary}")
    return path


def _authority_digests(root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in AUTHORITY_PATHS:
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), 16 * 1024 * 1024, relative
        )
        records[relative] = {"sha256": sha256_bytes(payload), "bytes": len(payload)}
    return records


def _load_document(root: Path, relative: str) -> Any:
    payload = _read_stable_file(
        root.joinpath(*relative.split("/")), 16 * 1024 * 1024, relative
    )
    return load_json_bytes(payload, relative)


def _matrix_row(matrix: dict[str, Any], identifier: str) -> dict[str, Any]:
    artifacts = matrix.get("artifacts")
    matches = (
        [
            row
            for row in artifacts
            if isinstance(row, dict) and row.get("id") == identifier
        ]
        if isinstance(artifacts, list)
        else []
    )
    if len(matches) != 1:
        raise ReleaseError(f"artifact matrix must contain exactly one {identifier} row")
    return matches[0]


def _load_configuration(root: Path) -> Configuration:
    root = root.resolve(strict=True)
    authority = _authority_digests(root)
    product = _load_document(root, "packaging/product-version.v1.json")
    matrix = _load_document(root, "packaging/artifact-matrix.v1.json")
    profile = _load_document(root, "packaging/development/local-macos-aarch64.v1.json")
    bottle_contract_document = _load_document(
        root, "packaging/contracts/homebrew-bottle.v1.json"
    )
    tap_contract_document = _load_document(
        root, "packaging/contracts/homebrew-tap.v1.json"
    )

    if (
        not isinstance(product, dict)
        or product.get("schema_version") != "cigar.product-version.v1"
        or product.get("release_state") != "development"
        or product.get("channel") != "development"
        or product.get("prerelease") is not True
        or product.get("published") is not False
        or product.get("supported") is not False
        or product.get("tag") is not None
        or not isinstance(product.get("version"), str)
        or product.get("context_abi") != "cigar.context.v1"
    ):
        raise ReleaseError(
            "product authority is not an unpublished development identity"
        )
    version = product["version"]
    context_abi = product["context_abi"]
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("release_state") != "development"
        or matrix.get("product_version") != version
        or matrix.get("context_abi") != context_abi
    ):
        raise ReleaseError("artifact matrix is stale relative to product authority")

    native = _matrix_row(matrix, NATIVE_ARTIFACT_ID)
    formula = _matrix_row(matrix, FORMULA_ARTIFACT_ID)
    bottle = _matrix_row(matrix, BOTTLE_ARTIFACT_ID)
    expected_producer = "python3 scripts/release/build_macos_homebrew_artifacts.py"
    expected_native_filename = f"cigar-{version}-{TARGET_TRIPLE}.tar.gz"
    expected_tap_filename = f"cigar-{version}-homebrew-tap.tar.gz"
    expected_bottle_filename = f"cigar--{version}.{BOTTLE_TAG}.bottle.tar.gz"
    if (
        native.get("kind") != "binary-archive"
        or native.get("filename") != expected_native_filename
        or native.get("contract") != "contracts/macos-runtime-archive.v1.json"
        or native.get("platform") != TARGET_TRIPLE
        or native.get("producer")
        != "python3 scripts/release/build_macos_aarch64_archive.py"
        or native.get("signature_purpose") != "macos-runtime-distribution"
        or native.get("install_target") != "bin"
        or native.get("evidence_map")
        != [
            "package-contract",
            "installed-artifact",
            "unprivileged",
            "offline",
            "upgrade",
            "uninstall",
            "sbom",
            "license",
            "signature",
            "platform-signing",
            "notarization",
            "provenance",
        ]
    ):
        raise ReleaseError("native archive row is incomplete or stale")
    if formula != {
        "id": FORMULA_ARTIFACT_ID,
        "kind": "homebrew-tap-archive",
        "filename": expected_tap_filename,
        "contract": "contracts/homebrew-tap.v1.json",
        "platform": TARGET_TRIPLE,
        "ecosystem": "homebrew",
        "producer": expected_producer,
        "signature_purpose": "homebrew-tap-source",
        "install_target": "tap/Formula/cigar.rb",
        "evidence_map": [
            "package-contract",
            "formula-syntax",
            "native-archive-binding",
            "bottle-digest-binding",
            "signature",
            "provenance",
        ],
        "required_for_release": True,
        "qualification": [
            "formula-syntax",
            "bottle-digest-binding",
            "clean-install",
            "offline",
            "signature",
            "provenance",
        ],
    }:
        raise ReleaseError("Homebrew formula/tap row is incomplete or stale")
    if bottle != {
        "id": BOTTLE_ARTIFACT_ID,
        "kind": "homebrew-bottle",
        "filename": expected_bottle_filename,
        "contract": "contracts/homebrew-bottle.v1.json",
        "platform": TARGET_TRIPLE,
        "ecosystem": "homebrew",
        "producer": expected_producer,
        "signature_purpose": "homebrew-bottle-distribution",
        "install_target": f"homebrew-cellar/cigar/{version}",
        "evidence_map": [
            "package-contract",
            "native-archive-binding",
            "installed-artifact",
            "unprivileged",
            "offline",
            "upgrade",
            "uninstall",
            "sbom",
            "license",
            "signature",
            "platform-signing",
            "notarization",
            "provenance",
        ],
        "required_for_release": True,
        "qualification": [
            "homebrew-bottle",
            "installed-artifact",
            "unprivileged",
            "offline",
            "upgrade",
            "uninstall",
            "sbom",
            "license",
            "signature",
            "platform-signing",
            "notarization",
            "provenance",
        ],
    }:
        raise ReleaseError("Homebrew bottle row is incomplete or stale")

    selected = profile.get("selected_artifacts") if isinstance(profile, dict) else None
    missing = profile.get("missing_artifacts") if isinstance(profile, dict) else None
    selected_by_id = (
        {row.get("id"): row for row in selected if isinstance(row, dict)}
        if isinstance(selected, list)
        else {}
    )
    if (
        not isinstance(profile, dict)
        or profile.get("schema_version") != "cigar.development-artifact-profile.v1"
        or profile.get("release_state") != "development"
        or profile.get("published") is not False
        or profile.get("supported") is not False
        or profile.get("target")
        != {
            "host_arch": "arm64",
            "host_os": "macos",
            "target_triple": TARGET_TRIPLE,
        }
        or selected_by_id.get(FORMULA_ARTIFACT_ID)
        != {
            "id": FORMULA_ARTIFACT_ID,
            "selection_group": "installer-metadata",
            "status": "planned",
            "built": False,
            "qualified": False,
        }
        or selected_by_id.get(BOTTLE_ARTIFACT_ID)
        != {
            "id": BOTTLE_ARTIFACT_ID,
            "selection_group": "installer-native",
            "status": "planned",
            "built": False,
            "qualified": False,
        }
        or missing != []
    ):
        raise ReleaseError(
            "development profile does not keep Homebrew artifacts unclaimed and sidecar-complete"
        )

    bottle_contract = _validate_contract(bottle_contract_document)
    tap_contract = _validate_contract(tap_contract_document)
    bottle_prefix = f"cigar/{version}"
    bottle_required = {
        f"{bottle_prefix}/.brew/cigar.rb",
        f"{bottle_prefix}/INSTALL_RECEIPT.json",
        f"{bottle_prefix}/bin/cigar",
        f"{bottle_prefix}/bin/cigard",
        f"{bottle_prefix}/bin/cigar-mcp",
        f"{bottle_prefix}/bin/cigar-claude-hook",
        f"{bottle_prefix}/etc/bash_completion.d/cigar",
        f"{bottle_prefix}/sbom.spdx.json",
        f"{bottle_prefix}/share/doc/cigar/LICENSE",
        f"{bottle_prefix}/share/doc/cigar/NOTICE",
        f"{bottle_prefix}/share/fish/vendor_completions.d/cigar.fish",
        f"{bottle_prefix}/share/man/man1/cigar.1",
        f"{bottle_prefix}/share/zsh/site-functions/_cigar",
    }
    if (
        bottle_contract.get("id") != "homebrew-bottle-v1"
        or bottle_contract.get("formats") != ["tar.gz"]
        or bottle_contract.get("checksum_manifest") is not None
        or not isinstance(bottle_contract.get("required"), list)
        or set(bottle_contract["required"]) != bottle_required
        or tap_contract.get("id") != "homebrew-tap-v1"
        or tap_contract.get("formats") != ["tar.gz"]
        or tap_contract.get("checksum_manifest")
        != {"path": "SHA256SUMS", "scope": "all-payload-files"}
    ):
        raise ReleaseError("Homebrew package contracts are incomplete or stale")

    license_payload = _read_stable_file(root / "LICENSE", 4 * 1024 * 1024, "LICENSE")
    notice_payload = _read_stable_file(root / "NOTICE", 4 * 1024 * 1024, "NOTICE")
    return Configuration(
        root=root,
        version=version,
        context_abi=context_abi,
        native_filename=expected_native_filename,
        bottle_filename=expected_bottle_filename,
        tap_filename=expected_tap_filename,
        bottle_contract=root / "packaging/contracts/homebrew-bottle.v1.json",
        tap_contract=root / "packaging/contracts/homebrew-tap.v1.json",
        authority=authority,
        license_payload=license_payload,
        notice_payload=notice_payload,
    )


def _validate_native_receipt(
    payload: bytes,
    configuration: Configuration,
    native_sha256: str,
    native_bytes: int,
    epoch: int,
) -> dict[str, Any]:
    receipt = load_json_bytes(payload, "native development build receipt")
    expected_claims = {
        "development_build": True,
        "distribution_signed": False,
        "notarized": False,
        "qualified": False,
        "published": False,
        "supported": False,
        "release": False,
    }
    expected_authority = {
        path: configuration.authority[path] for path in NATIVE_AUTHORITY_PATHS
    }
    expected_contract = {
        "path": "packaging/contracts/macos-runtime-archive.v1.json",
        "sha256": configuration.authority[
            "packaging/contracts/macos-runtime-archive.v1.json"
        ]["sha256"],
    }
    if (
        not isinstance(receipt, dict)
        or payload != canonical_json_bytes(receipt)
        or receipt.get("schema_version") != "cigar.development-native-archive-build.v1"
        or receipt.get("status") != "built-unqualified"
        or receipt.get("artifact_id") != NATIVE_ARTIFACT_ID
        or receipt.get("target") != TARGET_TRIPLE
        or receipt.get("product_version") != configuration.version
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("runtime_profile") != NATIVE_RUNTIME_PROFILE
        or receipt.get("source_date_epoch") != epoch
        or receipt.get("archive")
        != {
            "path": configuration.native_filename,
            "sha256": native_sha256,
            "bytes": native_bytes,
        }
        or receipt.get("contract") != expected_contract
        or receipt.get("authority") != expected_authority
        or receipt.get("payload_file_count") != 12
        or receipt.get("build_environment")
        != {
            "cargo_network_offline": True,
            "network_enforcement": MACOS_NO_EGRESS_ENFORCEMENT,
            "sandbox_launcher": str(MACOS_SANDBOX_EXEC),
            "sandbox_policy": MACOS_NO_EGRESS_POLICY,
        }
        or receipt.get("package_verification")
        != {
            "schema_version": "cigar.package-verification.v1",
            "status": "passed",
            "file_count": 12,
            "expanded_bytes": receipt.get("package_verification", {}).get(
                "expanded_bytes"
            )
            if isinstance(receipt.get("package_verification"), dict)
            else None,
        }
        or receipt.get("claims") != expected_claims
    ):
        raise ReleaseError("native development build receipt is stale or overclaims")
    verification = receipt["package_verification"]
    if (
        not isinstance(verification["expanded_bytes"], int)
        or isinstance(verification["expanded_bytes"], bool)
        or verification["expanded_bytes"] <= 0
    ):
        raise ReleaseError("native development package verification is malformed")
    source = receipt.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or not isinstance(source.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]) is None
        or not isinstance(source.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", source["tree_sha256"]) is None
        or source.get("committed") is not True
        or not isinstance(source.get("clean"), bool)
    ):
        raise ReleaseError("native development source identity is malformed")
    return receipt


def _native_members(
    payload: bytes, configuration: Configuration, epoch: int, source: dict[str, Any]
) -> dict[str, bytes]:
    expected = {
        "RELEASE-METADATA.json",
        "LICENSE",
        "NOTICE",
        "SHA256SUMS",
        "bin/cigar",
        "bin/cigard",
        "bin/cigar-mcp",
        "bin/cigar-claude-hook",
        "share/man/man1/cigar.1",
        "completions/cigar.bash",
        "completions/_cigar",
        "completions/cigar.fish",
    }
    observed: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive:
                name = safe_relative_path(member.name)
                if name in observed or name not in expected or not member.isfile():
                    raise ReleaseError(
                        f"native archive has an unexpected member: {name}"
                    )
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.mtime != epoch
                    or member.mode not in {0o644, 0o755}
                    or member.size <= 0
                    or member.size > 268435456
                ):
                    raise ReleaseError(
                        f"native archive member metadata is invalid: {name}"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseError(f"cannot read native archive member: {name}")
                with handle:
                    member_payload = handle.read(member.size + 1)
                if len(member_payload) != member.size:
                    raise ReleaseError(f"native archive member changed length: {name}")
                observed[name] = member_payload
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError(
            f"cannot parse native development archive: {error}"
        ) from error
    if set(observed) != expected:
        raise ReleaseError(
            "native development archive inventory mismatch; "
            f"missing={sorted(expected - set(observed))}"
        )
    metadata = load_json_bytes(observed["RELEASE-METADATA.json"], "native metadata")
    if (
        not isinstance(metadata, dict)
        or metadata.get("schema_version") != "cigar.release-metadata.v1"
        or metadata.get("artifact_id") != NATIVE_ARTIFACT_ID
        or metadata.get("product_version") != configuration.version
        or metadata.get("context_abi") != configuration.context_abi
        or metadata.get("source_date_epoch") != epoch
        or metadata.get("source") != source
        or metadata.get("contract")
        != "packaging/contracts/macos-runtime-archive.v1.json"
        or metadata.get("contract_sha256")
        != configuration.authority["packaging/contracts/macos-runtime-archive.v1.json"][
            "sha256"
        ]
    ):
        raise ReleaseError("native archive metadata is stale or malformed")
    if (
        observed["LICENSE"] != configuration.license_payload
        or observed["NOTICE"] != configuration.notice_payload
    ):
        raise ReleaseError(
            "native archive license assets differ from repository authority"
        )
    _validate_macho_arm64(observed["bin/cigar"], "native cigar")
    _validate_macho_arm64(observed["bin/cigard"], "native cigard")
    _validate_macho_arm64(observed["bin/cigar-mcp"], "native cigar-mcp")
    _validate_macho_arm64(observed["bin/cigar-claude-hook"], "native cigar-claude-hook")
    return observed


def _runtime_payload(native: dict[str, bytes]) -> dict[str, dict[str, object]]:
    return {
        name: {
            "path": f"bin/{name}",
            "sha256": sha256_bytes(native[f"bin/{name}"]),
            "bytes": len(native[f"bin/{name}"]),
        }
        for name in ("cigar", "cigard", "cigar-mcp", "cigar-claude-hook")
    }


def _formula(
    configuration: Configuration,
    native_sha256: str,
    bottle_sha256: str | None,
) -> bytes:
    bottle_block = ""
    if bottle_sha256 is not None:
        bottle_block = f'''\n  bottle do
    root_url "{DEVELOPMENT_DOWNLOAD_ROOT}/homebrew"
    rebuild {BOTTLE_REBUILD}
    sha256 cellar: :{BOTTLE_CELLAR}, {BOTTLE_TAG}: "{bottle_sha256}"
  end
'''
    formula = f'''class Cigar < Formula
  desc "Deterministic context infrastructure for AI agents"
  homepage "https://hol.org/cigar"
  url "{DEVELOPMENT_DOWNLOAD_ROOT}/{configuration.native_filename}"
  version "{configuration.version}"
  sha256 "{native_sha256}"
  license "Apache-2.0"
{bottle_block}
  depends_on arch: :arm64
  depends_on macos: :sequoia

  def install
    bin.install "bin/cigar", "bin/cigard", "bin/cigar-mcp", "bin/cigar-claude-hook"
    man1.install "share/man/man1/cigar.1"
    bash_completion.install "completions/cigar.bash" => "cigar"
    zsh_completion.install "completions/_cigar"
    fish_completion.install "completions/cigar.fish"
    (share/"doc/cigar").install "LICENSE", "NOTICE"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/cigar --version")
    assert_match '"protocol_version":"2025-06-18"', shell_output("#{{bin}}/cigar-mcp schema-noop")
    assert_match '"effect_precheck":"fail_closed"', shell_output("#{{bin}}/cigar-claude-hook schema-noop")
  end
end
'''.encode("utf-8")
    if (
        not formula.endswith(b"\n")
        or b"\r" in formula
        or not 1 <= len(formula) <= MAX_FORMULA_BYTES
    ):
        raise ReleaseError("generated Homebrew formula is malformed")
    return formula


def _entries_digest(entries: list[Entry]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item.path.encode("utf-8")):
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(entry.payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{entry.mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.payload).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def _validate_entries(entries: list[Entry]) -> None:
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        name = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", name).casefold()
        if name in names or alias in aliases:
            raise ReleaseError(f"duplicate or portable-colliding Homebrew path: {name}")
        if entry.mode not in {0o644, 0o755} or not entry.payload:
            raise ReleaseError(
                f"Homebrew entry has invalid mode or empty payload: {name}"
            )
        names.add(name)
        aliases.add(alias)


def _write_archive(path: Path, entries: list[Entry], epoch: int) -> None:
    _validate_entries(entries)
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged Homebrew artifact: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for entry in sorted(
                        entries, key=lambda item: item.path.encode("utf-8")
                    ):
                        information = tarfile.TarInfo(entry.path)
                        information.size = len(entry.payload)
                        information.mode = entry.mode
                        information.mtime = epoch
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        archive.addfile(information, io.BytesIO(entry.payload))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _install_receipt(configuration: Configuration, epoch: int) -> bytes:
    """Return a deterministic Tab document accepted by Homebrew 6 bottle readers."""

    return canonical_json_bytes(
        {
            "homebrew_version": HOMEBREW_RECEIPT_COMPATIBILITY_VERSION,
            "used_options": [],
            "unused_options": [],
            "built_as_bottle": True,
            "poured_from_bottle": False,
            "loaded_from_api": False,
            "loaded_from_internal_api": False,
            "installed_on_request": False,
            "changed_files": [],
            "time": None,
            "source_modified_time": epoch,
            "compiler": "rustc",
            "aliases": [],
            "runtime_dependencies": [],
            "source": {
                "spec": "stable",
                "path": "Formula/cigar.rb",
                "tap": None,
                "tap_git_head": None,
                "versions": {
                    "stable": configuration.version,
                    "head": None,
                    "version_scheme": 0,
                    "compatibility_version": None,
                },
            },
            "arch": "arm64",
            "built_on": {
                "os": "Macintosh",
                "os_version": f"macOS {BOTTLE_MACOS_VERSION}",
                "cpu_family": "arm64",
                "xcode": None,
                "clt": None,
                "preferred_perl": None,
            },
        }
    )


def _bottle_sbom(configuration: Configuration, native_sha256: str, epoch: int) -> bytes:
    """Return the source-bound SPDX document current Homebrew bottles carry."""

    created = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    source_id = "SPDXRef-Archive-cigar-src"
    return canonical_json_bytes(
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "name": f"SBOM-SPDX-cigar-{configuration.version}",
            "creationInfo": {
                "created": created,
                "creators": ["Tool: CIGAR deterministic development Homebrew producer"],
            },
            "dataLicense": "CC0-1.0",
            "documentNamespace": (
                f"https://cigar.invalid/spdx/cigar-{configuration.version}.json"
            ),
            "documentDescribes": [source_id],
            "files": [],
            "packages": [
                {
                    "SPDXID": source_id,
                    "name": "cigar",
                    "versionInfo": configuration.version,
                    "filesAnalyzed": False,
                    "licenseDeclared": "Apache-2.0",
                    "licenseConcluded": "Apache-2.0",
                    "downloadLocation": (
                        f"{DEVELOPMENT_DOWNLOAD_ROOT}/{configuration.native_filename}"
                    ),
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceLocator": (
                                f"pkg:brew/cigar@{configuration.version}"
                            ),
                            "referenceType": "purl",
                        }
                    ],
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": native_sha256}
                    ],
                }
            ],
            "relationships": [],
        }
    )


def _bottle_entries(
    configuration: Configuration,
    native: dict[str, bytes],
    formula: bytes,
    native_sha256: str,
    epoch: int,
) -> list[Entry]:
    prefix = f"cigar/{configuration.version}"
    entries = [
        Entry(f"{prefix}/.brew/cigar.rb", formula, 0o644),
        Entry(
            f"{prefix}/INSTALL_RECEIPT.json",
            _install_receipt(configuration, epoch),
            0o644,
        ),
        Entry(f"{prefix}/bin/cigar", native["bin/cigar"], 0o755),
        Entry(f"{prefix}/bin/cigard", native["bin/cigard"], 0o755),
        Entry(f"{prefix}/bin/cigar-mcp", native["bin/cigar-mcp"], 0o755),
        Entry(
            f"{prefix}/bin/cigar-claude-hook",
            native["bin/cigar-claude-hook"],
            0o755,
        ),
        Entry(
            f"{prefix}/etc/bash_completion.d/cigar",
            native["completions/cigar.bash"],
            0o644,
        ),
        Entry(f"{prefix}/share/doc/cigar/LICENSE", native["LICENSE"], 0o644),
        Entry(f"{prefix}/share/doc/cigar/NOTICE", native["NOTICE"], 0o644),
        Entry(
            f"{prefix}/sbom.spdx.json",
            _bottle_sbom(configuration, native_sha256, epoch),
            0o644,
        ),
        Entry(
            f"{prefix}/share/fish/vendor_completions.d/cigar.fish",
            native["completions/cigar.fish"],
            0o644,
        ),
        Entry(
            f"{prefix}/share/man/man1/cigar.1",
            native["share/man/man1/cigar.1"],
            0o644,
        ),
        Entry(
            f"{prefix}/share/zsh/site-functions/_cigar",
            native["completions/_cigar"],
            0o644,
        ),
    ]
    relocation_markers = (
        b"/opt/homebrew",
        b"/usr/local/Cellar",
        b"/opt/homebrew/Cellar",
    )
    for entry in entries:
        if any(marker in entry.payload for marker in relocation_markers):
            raise ReleaseError(
                f"bottle payload is not eligible for any-skip-relocation: {entry.path}"
            )
    return entries


def _tap_entries(
    configuration: Configuration,
    formula: bytes,
    bottle_sha256: str,
    bottle_bytes: int,
    native_sha256: str,
    native_bytes: int,
    source: dict[str, Any],
    epoch: int,
) -> list[Entry]:
    formula_reference = {
        "path": "Formula/cigar.rb",
        "sha256": sha256_bytes(formula),
        "bytes": len(formula),
    }
    tap_metadata = canonical_json_bytes(
        {
            "schema_version": "cigar.development-homebrew-tap.v1",
            "release_state": "development",
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "platform": TARGET_TRIPLE,
            "formula": formula_reference,
            "source_archive": {
                "artifact_id": NATIVE_ARTIFACT_ID,
                "filename": configuration.native_filename,
                "sha256": native_sha256,
                "bytes": native_bytes,
                "distribution_signed": False,
                "notarized": False,
                "runtime_members": [
                    "bin/cigar",
                    "bin/cigard",
                    "bin/cigar-mcp",
                    "bin/cigar-claude-hook",
                ],
            },
            "bottle": {
                "artifact_id": BOTTLE_ARTIFACT_ID,
                "filename": configuration.bottle_filename,
                "sha256": bottle_sha256,
                "bytes": bottle_bytes,
                "tag": BOTTLE_TAG,
                "rebuild": BOTTLE_REBUILD,
                "cellar": BOTTLE_CELLAR,
            },
            "published": False,
            "supported": False,
        }
    )
    base = [
        Entry("Formula/cigar.rb", formula, 0o644),
        Entry("HOMEBREW-TAP-METADATA.json", tap_metadata, 0o644),
        Entry("LICENSE", configuration.license_payload, 0o644),
        Entry("NOTICE", configuration.notice_payload, 0o644),
    ]
    checksums = "".join(
        f"{sha256_bytes(entry.payload)}  {entry.path}\n"
        for entry in sorted(base, key=lambda item: item.path.encode("utf-8"))
    ).encode("ascii")
    with_checksums = [*base, Entry("SHA256SUMS", checksums, 0o644)]
    release_metadata = canonical_json_bytes(
        {
            "schema_version": "cigar.release-metadata.v1",
            "artifact_id": FORMULA_ARTIFACT_ID,
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": epoch,
            "source": source,
            "input_tree_sha256": _entries_digest(with_checksums),
            "input_file_count": len(with_checksums),
            "contract": "packaging/contracts/homebrew-tap.v1.json",
            "contract_sha256": configuration.authority[
                "packaging/contracts/homebrew-tap.v1.json"
            ]["sha256"],
        }
    )
    return [Entry("RELEASE-METADATA.json", release_metadata, 0o644), *with_checksums]


def produce(arguments: argparse.Namespace) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    host = _validate_bottle_host(_require_host())
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    configuration = _load_configuration(root)
    native_path = _absolute_input(
        arguments.native_archive, "native archive", root, evidence_root
    )
    receipt_path = _absolute_input(
        arguments.native_build_receipt, "native build receipt", root, evidence_root
    )
    if (
        native_path == receipt_path
        or native_path.name != configuration.native_filename
        or receipt_path.name != "macos-aarch64-development-build.json"
    ):
        raise ReleaseError("native archive input identity is invalid")

    native_payload = _read_stable_file(native_path, MAX_ARCHIVE_BYTES, "native archive")
    native_sha256 = sha256_bytes(native_payload)
    native_receipt_payload = _read_stable_file(
        receipt_path, MAX_RECEIPT_BYTES, "native build receipt"
    )
    native_receipt_sha256 = sha256_bytes(native_receipt_payload)
    native_receipt = _validate_native_receipt(
        native_receipt_payload,
        configuration,
        native_sha256,
        len(native_payload),
        epoch,
    )
    source = native_receipt["source"]

    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(prefix="cigar-homebrew-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Bottle/formula staging must remain private until exact-byte verification finishes.
            # 0700 is the intended least-privilege mode, not a permissive default.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                scratch,
                0o700,
            )
            staged_native = scratch / configuration.native_filename
            staged_native.write_bytes(native_payload)
            os.chmod(staged_native, 0o600)
            native_verification = verify_package(
                staged_native,
                root / "packaging/contracts/macos-runtime-archive.v1.json",
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            native_members = _native_members(
                native_payload, configuration, epoch, source
            )
            runtime_payload = _runtime_payload(native_members)
            if native_receipt.get("runtime_payload") != runtime_payload:
                raise ReleaseError(
                    "native development build receipt does not bind every runtime binary"
                )

            embedded_formula = _formula(configuration, native_sha256, None)
            bottle_entries = _bottle_entries(
                configuration,
                native_members,
                embedded_formula,
                native_sha256,
                epoch,
            )
            staged_bottle = scratch / configuration.bottle_filename
            _write_archive(staged_bottle, bottle_entries, epoch)
            bottle_payload = _read_stable_file(
                staged_bottle, MAX_ARCHIVE_BYTES, "staged Homebrew bottle"
            )
            bottle_sha256 = sha256_bytes(bottle_payload)
            bottle_verification = verify_package(
                staged_bottle,
                configuration.bottle_contract,
                None,
                None,
                epoch,
            )

            tap_formula = _formula(configuration, native_sha256, bottle_sha256)
            tap_entries = _tap_entries(
                configuration,
                tap_formula,
                bottle_sha256,
                len(bottle_payload),
                native_sha256,
                len(native_payload),
                source,
                epoch,
            )
            staged_tap = scratch / configuration.tap_filename
            _write_archive(staged_tap, tap_entries, epoch)
            tap_payload = _read_stable_file(
                staged_tap, MAX_ARCHIVE_BYTES, "staged Homebrew tap archive"
            )
            tap_sha256 = sha256_bytes(tap_payload)
            tap_verification = verify_package(
                staged_tap,
                configuration.tap_contract,
                configuration.version,
                configuration.context_abi,
                epoch,
            )

            if _authority_digests(root) != configuration.authority:
                raise ReleaseError(
                    "Homebrew build authority changed during construction"
                )
            for staged, expected_payload, label in (
                (staged_bottle, bottle_payload, "Homebrew bottle"),
                (staged_tap, tap_payload, "Homebrew tap archive"),
            ):
                observed = _read_stable_file(staged, MAX_ARCHIVE_BYTES, label)
                if observed != expected_payload:
                    raise ReleaseError(f"{label} changed after package verification")

            bottle_reference = workspace.attach_file(
                staged_bottle,
                configuration.bottle_filename,
                expected_sha256=bottle_sha256,
                expected_bytes=len(bottle_payload),
            )
            tap_reference = workspace.attach_file(
                staged_tap,
                configuration.tap_filename,
                expected_sha256=tap_sha256,
                expected_bytes=len(tap_payload),
            )

        receipt = {
            "schema_version": "cigar.development-homebrew-build.v1",
            "status": "built-unqualified",
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "target": TARGET_TRIPLE,
            "source_date_epoch": epoch,
            "source": source,
            "host": host,
            "input_native_archive": {
                "artifact_id": NATIVE_ARTIFACT_ID,
                "path": configuration.native_filename,
                "sha256": native_sha256,
                "bytes": len(native_payload),
                "build_receipt": {
                    "filename": receipt_path.name,
                    "sha256": native_receipt_sha256,
                    "bytes": len(native_receipt_payload),
                },
                "runtime_payload": runtime_payload,
            },
            "artifacts": [
                {
                    "artifact_id": FORMULA_ARTIFACT_ID,
                    "kind": "homebrew-tap-archive",
                    **tap_reference.as_dict(),
                    "contract": {
                        "path": "packaging/contracts/homebrew-tap.v1.json",
                        "sha256": configuration.authority[
                            "packaging/contracts/homebrew-tap.v1.json"
                        ]["sha256"],
                    },
                    "package_verification": {
                        key: tap_verification[key]
                        for key in (
                            "schema_version",
                            "status",
                            "file_count",
                            "expanded_bytes",
                        )
                    },
                },
                {
                    "artifact_id": BOTTLE_ARTIFACT_ID,
                    "kind": "homebrew-bottle",
                    **bottle_reference.as_dict(),
                    "contract": {
                        "path": "packaging/contracts/homebrew-bottle.v1.json",
                        "sha256": configuration.authority[
                            "packaging/contracts/homebrew-bottle.v1.json"
                        ]["sha256"],
                    },
                    "package_verification": {
                        key: bottle_verification[key]
                        for key in (
                            "schema_version",
                            "status",
                            "file_count",
                            "expanded_bytes",
                        )
                    },
                },
            ],
            "native_package_verification": {
                key: native_verification[key]
                for key in ("schema_version", "status", "file_count", "expanded_bytes")
            },
            "bottle_binding": {
                "tag": BOTTLE_TAG,
                "rebuild": BOTTLE_REBUILD,
                "cellar": BOTTLE_CELLAR,
                "cellar_path": f"cigar/{configuration.version}",
                "formula_member": f"cigar/{configuration.version}/.brew/cigar.rb",
                "install_receipt_member": (
                    f"cigar/{configuration.version}/INSTALL_RECEIPT.json"
                ),
                "receipt_format_compatibility": (
                    f"homebrew-{HOMEBREW_RECEIPT_COMPATIBILITY_VERSION}"
                ),
                "sbom_member": f"cigar/{configuration.version}/sbom.spdx.json",
                "sbom_scope": "development-source-binding",
                "installed_runtime_members": [
                    "bin/cigar",
                    "bin/cigard",
                    "bin/cigar-mcp",
                    "bin/cigar-claude-hook",
                ],
            },
            "authority": configuration.authority,
            "external_requirements": {
                "native_code_signing": "not-evidenced",
                "notarization": "not-evidenced",
                "artifact_signatures": "not-evidenced",
                "installed_byte_qualification": "not-evidenced",
                "homebrew_publication": "not-performed",
            },
            "claims": {
                "development_build": True,
                "release_built": False,
                "distribution_signed": False,
                "notarized": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }
        workspace.write_json(BUILD_RECEIPT, receipt)
        workspace.read_files(
            {configuration.bottle_filename, configuration.tap_filename, BUILD_RECEIPT},
            strict_read_only=True,
        )
        return receipt
    finally:
        workspace.close()


def main() -> int:
    receipt = produce(parse_arguments())
    print(canonical_json_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"macOS Homebrew development build failed: {error}") from error
