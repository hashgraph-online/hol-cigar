#!/usr/bin/env python3
"""Build deterministic, unsigned macOS qualification-tool packages."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    git_state,
    load_json,
    process_failure_summary,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    tree_digest,
)
from verify_package import verify as verify_package


TARGET_TRIPLE = "aarch64-apple-darwin"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
FIXED_CIGARBENCH_PYTHON = "/opt/homebrew/bin/python3"
MACOS_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
MACOS_NO_EGRESS_POLICY = "(version 1)(allow default)(deny network*)"
MACOS_NO_EGRESS_ENFORCEMENT = "darwin-sandbox-exec-deny-network-v1"
DEVELOPMENT_COMMON_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
)
HONEY_COMMON_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
)
HONEY_PROFILE_ID = "cigar.honey.local-developer-preview.macos-arm64.v1"
HONEY_INTERNAL_INPUT_ID = "qualification-tools"
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/target/**",
)


@dataclass(frozen=True)
class PackageEntry:
    path: str
    payload: bytes
    mode: int


@dataclass(frozen=True)
class ToolSpec:
    selector: str
    artifact_id: str
    kind: str
    filename_template: str
    contract_relative: str
    producer: str
    signature_purpose: str
    install_target: str
    selection_group: str
    receipt_name: str
    evidence_map: tuple[str, ...]
    qualification: tuple[str, ...]
    source_includes: tuple[str, ...]


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    spec: ToolSpec
    version: str
    context_abi: str
    filename: str
    contract_path: Path
    authority: dict[str, dict[str, object]]
    assets: dict[str, bytes]
    honey: bool


@dataclass(frozen=True)
class BuiltTool:
    entries: tuple[PackageEntry, ...]
    tools: tuple[dict[str, object], ...]
    invocation_probes: tuple[dict[str, object], ...]


CONFORMANCE_EVIDENCE = (
    "package-contract",
    "native-architecture",
    "asset-inventory",
    "runner-invocation",
    "installed-artifact",
    "unprivileged",
    "offline",
    "uninstall",
    "conformance",
    "sbom",
    "license",
    "signature",
    "platform-signing",
    "notarization",
    "provenance",
)
BENCHMARK_EVIDENCE = (
    "package-contract",
    "launcher-invocation",
    "asset-inventory",
    "installed-artifact",
    "unprivileged",
    "offline",
    "uninstall",
    "benchmark-efficacy",
    "sbom",
    "license",
    "signature",
    "platform-signing",
    "notarization",
    "provenance",
)
COMMON_QUALIFICATION = (
    "archive-contract",
    "installed-artifact",
    "unprivileged",
    "offline",
    "uninstall",
)


SPECS = {
    "conformance": ToolSpec(
        selector="conformance",
        artifact_id="cigar-conformance-macos-aarch64",
        kind="conformance-runner-archive",
        filename_template="cigar-conformance-{version}-aarch64-apple-darwin.tar.gz",
        contract_relative="packaging/contracts/macos-conformance-runner.v1.json",
        producer=(
            "python3 scripts/release/build_macos_qualification_tools.py conformance"
        ),
        signature_purpose="macos-conformance-tool-distribution",
        install_target="bin/cigar-conformance",
        selection_group="qualification-conformance",
        receipt_name="macos-conformance-development-build.json",
        evidence_map=CONFORMANCE_EVIDENCE,
        qualification=(
            *COMMON_QUALIFICATION,
            "conformance",
            "sbom",
            "license",
            "signature",
            "platform-signing",
            "notarization",
            "provenance",
        ),
        source_includes=(
            ".cargo/**",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "rustfmt.toml",
            "clippy.toml",
            "crates/**",
            "conformance/runner/**",
            "conformance/profiles/**",
            "conformance/vectors/**",
            "conformance/expected/**",
            "prd.md",
            "tests/invariants.yaml",
            "reports/conformance-result.v1.json",
            "schemas/**",
            "scripts/release/build_macos_qualification_tools.py",
            "scripts/release/evidence_workspace.py",
            "scripts/release/release_lib.py",
            "scripts/release/verify_package.py",
            "packaging/contracts/macos-conformance-runner.v1.json",
            "packaging/product-version.v1.json",
            "packaging/artifact-matrix.v1.json",
            "packaging/development/local-macos-aarch64.v1.json",
            "LICENSE",
            "NOTICE",
        ),
    ),
    "cigarbench": ToolSpec(
        selector="cigarbench",
        artifact_id="cigarbench-macos-aarch64",
        kind="benchmark-tool-archive",
        filename_template="cigarbench-{version}-aarch64-apple-darwin.tar.gz",
        contract_relative="packaging/contracts/macos-cigarbench-tool.v1.json",
        producer="python3 scripts/release/build_macos_qualification_tools.py cigarbench",
        signature_purpose="macos-cigarbench-tool-distribution",
        install_target="bin/cigarbench",
        selection_group="qualification-benchmark",
        receipt_name="macos-cigarbench-development-build.json",
        evidence_map=BENCHMARK_EVIDENCE,
        qualification=(
            *COMMON_QUALIFICATION,
            "benchmark",
            "sbom",
            "license",
            "signature",
            "platform-signing",
            "notarization",
            "provenance",
        ),
        source_includes=(
            ".cargo/**",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "crates/**",
            "benches/cigarbench/cigarbench.py",
            "benches/cigarbench/local_scale.py",
            "benches/cigarbench/local_scale_driver/**",
            "benches/cigarbench/profiles/**",
            "benches/cigarbench/performance.py",
            "benches/cigarbench/canaries.json",
            "benches/cigarbench/datasets/**",
            "benches/cigarbench/pins/**",
            "benches/cigarbench/schemas/**",
            "baselines/cigarbench/manifest.json",
            "baselines/cigarbench/qualify_matrix.py",
            "scripts/release/evidence_workspace.py",
            "scripts/release/build_macos_qualification_tools.py",
            "scripts/release/release_lib.py",
            "scripts/release/verify_package.py",
            "packaging/contracts/macos-cigarbench-tool.v1.json",
            "packaging/product-version.v1.json",
            "packaging/artifact-matrix.v1.json",
            "packaging/development/local-macos-aarch64.v1.json",
            "LICENSE",
            "NOTICE",
        ),
    ),
}


CONFORMANCE_ASSETS = {
    "share/cigar/prd.md": "prd.md",
    "share/cigar/tests/invariants.yaml": "tests/invariants.yaml",
    "share/cigar/reports/conformance-result.v1.json": "reports/conformance-result.v1.json",
    "share/cigar/crates/xtask/src/lib.rs": "crates/xtask/src/lib.rs",
    "share/cigar/conformance/runner/tests/conformance.rs": (
        "conformance/runner/tests/conformance.rs"
    ),
    "share/cigar/conformance/runner/tests/traceability.rs": (
        "conformance/runner/tests/traceability.rs"
    ),
    "share/cigar/conformance/profiles/requirements-v1.json": (
        "conformance/profiles/requirements-v1.json"
    ),
    "share/cigar/conformance/profiles/faults-v1.json": (
        "conformance/profiles/faults-v1.json"
    ),
    "share/cigar/conformance/runner/src/bin/cigar-conformance-faulty.rs": (
        "conformance/runner/src/bin/cigar-conformance-faulty.rs"
    ),
    "share/cigar/conformance/profiles/v1.json": "conformance/profiles/v1.json",
    "share/cigar/conformance/vectors/v1/core-v1.json": (
        "conformance/vectors/v1/core-v1.json"
    ),
    "share/cigar/conformance/vectors/v1/fixture.toml": (
        "conformance/vectors/v1/fixture.toml"
    ),
    **{
        f"share/cigar/conformance/expected/{name}": f"conformance/expected/{name}"
        for name in (
            "cigar-catalog-v1.txt",
            "cigar-compiler-v1.txt",
            "cigar-core-v1.txt",
            "cigar-effect-v1.txt",
            "cigar-handoff-v1.txt",
            "cigar-replay-v1.txt",
            "cigar-runtime-claude-code-v1.txt",
            "cigar-service-v1.txt",
        )
    },
}
CONFORMANCE_BINARIES = (
    "bin/cigar-conformance",
    "bin/cigar-install-qualifier",
)
BENCHMARK_SOURCES = (
    "benches/cigarbench/cigarbench.py",
    "benches/cigarbench/local_scale.py",
    "benches/cigarbench/performance.py",
    "benches/cigarbench/canaries.json",
    "benches/cigarbench/datasets/agent-handoff-v1.json",
    "benches/cigarbench/datasets/catalog-mutation-v1.json",
    "benches/cigarbench/datasets/crossruntime-replay-v1.json",
    "benches/cigarbench/datasets/effect-crash-v1.json",
    "benches/cigarbench/datasets/longrepo-change-v1.json",
    "benches/cigarbench/datasets/manifest.json",
    "benches/cigarbench/datasets/multiproject-switch-v1.json",
    "benches/cigarbench/datasets/needle-distractor-v1.json",
    "benches/cigarbench/datasets/policy-boundary-v1.json",
    "benches/cigarbench/datasets/temporal-truth-v1.json",
    "benches/cigarbench/pins/deterministic-consumer-v1.json",
    "benches/cigarbench/schemas/performance-attestation-v1.schema.json",
    "benches/cigarbench/schemas/raw-event-v1.schema.json",
    "benches/cigarbench/schemas/local-scale-binding-v1.schema.json",
    "benches/cigarbench/schemas/local-scale-preflight-v1.schema.json",
    "benches/cigarbench/schemas/local-scale-result-v1.schema.json",
    "benches/cigarbench/profiles/large-local-v1.json",
    "baselines/cigarbench/manifest.json",
    "baselines/cigarbench/qualify_matrix.py",
    "scripts/release/evidence_workspace.py",
)
BENCHMARK_ASSETS = {
    f"libexec/cigarbench/{relative}": relative for relative in BENCHMARK_SOURCES
}


CONFORMANCE_README = b"""# CIGAR macOS qualification tools development package

This is an unsigned, unpublished, unsupported development package for Apple-silicon macOS.
It does not establish candidate, installed-artifact, conformance, signing, notarization,
publication, support, or release qualification.

Install `bin/cigar-conformance`, `bin/cigar-install-qualifier`, and the complete
`share/cigar` tree without changing their relative inventory. Pass the packaged vector
directory explicitly, for example:

    cigar-conformance run --profile cigar-core-v1 --vectors <share>/cigar/conformance/vectors/v1 ...

Profiles and expected-result summaries are packaged as review material. A passing invocation-only
probe is not a conformance result; qualification must run against exact installed candidate bytes.
The packaged PRD and invariant manifest make the normative baseline independently checkable:

    cigar-conformance traceability --root <share>/cigar --manifest tests/invariants.yaml

The install qualifier is a separate artifact-bound driver for `qualify_install.py`; it runs only
inside that caller's private macOS no-egress workspace and emits no passing receipt until the real
installed CLI, daemon, restart, backup/restore, recovery-contract, and retained-state migration
checks all pass.
"""

BENCHMARK_README = b"""# CIGARBench development tool package

This is an unsigned, unpublished, unsupported development package for Apple-silicon macOS.
It does not establish candidate, installed-artifact, benchmark efficacy, signing, notarization,
publication, support, or release qualification. No benchmark is executed by the package producer.

The three standard-library-only launchers are `cigarbench`, `cigarbench-performance`, and
`cigarbench-matrix`. The fourth tool, `cigarbench-local-scale`, is a native arm64 Rust executable
that runs only the exact immutable large-local physical qualification profile. The Python tools
require the reviewed `/opt/homebrew/bin/python3` interpreter at Python
3.11 or newer and always invoke it with isolated startup and site loading disabled. Keep `bin` and
`libexec/cigarbench` in their packaged relative layout.
Datasets, schemas, comparator baselines, pins, and the canary registry are exact package members;
callers must still provide independently controlled seeds, evaluator keys, installed consumer
bytes, raw measurements, and pinned-host evidence for any qualifying run.
Each launcher accepts a global `--evidence-dir` before its subcommand or
`CIGAR_EVIDENCE_DIR`; protected outputs are relative, create-new, private,
read-only external attachments with explicitly non-qualifying publication receipts.
"""


def _launcher_bytes() -> bytes:
    if FIXED_CIGARBENCH_PYTHON != "/opt/homebrew/bin/python3":
        raise ReleaseError("fixed CIGARBench interpreter policy was altered")
    return f"""#!/bin/sh
set -eu
IFS=' {chr(9)}
'
export IFS
PATH=/usr/bin:/bin
export PATH
unset ENV BASH_ENV CDPATH PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE
unset PYTHONINSPECT PYTHONWARNINGS PYTHONBREAKPOINT PYTHONSAFEPATH
case "$0" in
  */*) launcher_dir=${{0%/*}} ;;
  *) printf '%s\\n' 'cigarbench launcher path is invalid' >&2; exit 2 ;;
esac
launcher_dir=$(CDPATH= cd -P "$launcher_dir" 2>/dev/null && pwd -P) || {{
  printf '%s\\n' 'cigarbench launcher directory is unavailable' >&2
  exit 2
}}
root=${{launcher_dir%/*}}
case "${{0##*/}}" in
  cigarbench) target="$root/libexec/cigarbench/benches/cigarbench/cigarbench.py" ;;
  cigarbench-performance) target="$root/libexec/cigarbench/benches/cigarbench/performance.py" ;;
  cigarbench-matrix) target="$root/libexec/cigarbench/baselines/cigarbench/qualify_matrix.py" ;;
  *) printf '%s\\n' 'cigarbench launcher identity is invalid' >&2; exit 2 ;;
esac
target_dir=${{target%/*}}
target_name=${{target##*/}}
target_dir=$(CDPATH= cd -P "$target_dir" 2>/dev/null && pwd -P) || {{
  printf '%s\\n' 'cigarbench harness directory is unavailable' >&2
  exit 2
}}
case "$target_dir/" in
  "$root/libexec/cigarbench/"*) ;;
  *) printf '%s\\n' 'cigarbench harness escaped its install root' >&2; exit 2 ;;
esac
target="$target_dir/$target_name"
test -f "$target" && test ! -L "$target" || {{
  printf '%s\\n' 'cigarbench installed harness is unavailable' >&2
  exit 2
}}
exec {FIXED_CIGARBENCH_PYTHON} -B -I -S "$target" "$@"
""".encode("ascii")


ToolBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace], BuiltTool
]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=tuple(SPECS))
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external empty output workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--protoc", type=Path)
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
    if not selected.is_absolute():
        raise ReleaseError("evidence directory must be an absolute path")
    return selected


def _require_host() -> dict[str, str]:
    machine = platform.machine().casefold()
    if sys.platform != "darwin" or machine not in {"arm64", "aarch64"}:
        raise ReleaseError(
            "the qualification-tool producer requires Apple-silicon macOS; "
            f"observed platform={sys.platform} architecture={machine}"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": platform.mac_ver()[0],
    }


def _read_stable_file(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise ReleaseError(
                f"{label} is not a bounded owner-controlled regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds {maximum} bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ReleaseError(f"{label} changed while it was read")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ReleaseError(f"{label} changed length while it was read")
        return payload
    except OSError as error:
        raise ReleaseError(f"cannot securely read {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _authority_paths(spec: ToolSpec, *, honey: bool = True) -> tuple[str, ...]:
    common = (
        HONEY_COMMON_AUTHORITY_PATHS if honey else DEVELOPMENT_COMMON_AUTHORITY_PATHS
    )
    return (*common, spec.contract_relative)


def _authority_digests(
    root: Path, spec: ToolSpec, *, honey: bool = True
) -> dict[str, dict[str, object]]:
    return {
        relative: {
            "sha256": sha256_bytes(
                payload := _read_stable_file(
                    root.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, relative
                )
            ),
            "bytes": len(payload),
        }
        for relative in _authority_paths(spec, honey=honey)
    }


def _matrix_row(spec: ToolSpec, version: str) -> dict[str, Any]:
    return {
        "id": spec.artifact_id,
        "kind": spec.kind,
        "filename": spec.filename_template.format(version=version),
        "contract": spec.contract_relative.removeprefix("packaging/"),
        "platform": TARGET_TRIPLE,
        "producer": spec.producer,
        "signature_purpose": spec.signature_purpose,
        "install_target": spec.install_target,
        "evidence_map": list(spec.evidence_map),
        "required_for_release": True,
        "qualification": list(spec.qualification),
    }


def _honey_internal_input(spec: ToolSpec, version: str) -> dict[str, Any]:
    if spec.selector != "conformance":
        raise ReleaseError(
            "Honey selects only the bounded conformance qualification tool"
        )
    return {
        "id": HONEY_INTERNAL_INPUT_ID,
        "evidence_class": "package",
        "required": True,
        "public_attachment": False,
        "artifact_id": spec.artifact_id,
        "kind": spec.kind,
        "filename": spec.filename_template.format(version=version),
        "contract": spec.contract_relative,
        "producer": [
            "python3",
            "scripts/release/build_macos_qualification_tools.py",
            spec.selector,
        ],
        "target": TARGET_TRIPLE,
        "workspace": "qualification-tools",
        "receipt": {
            "required": True,
            "schema_version": "cigar.development-qualification-tool-build.v1",
            "filename": spec.receipt_name,
        },
    }


def _source_includes(spec: ToolSpec, *, honey: bool) -> tuple[str, ...]:
    if not honey:
        return spec.source_includes
    replaced = tuple(
        relative
        for relative in spec.source_includes
        if relative
        not in {
            "packaging/artifact-matrix.v1.json",
            "packaging/development/local-macos-aarch64.v1.json",
        }
    )
    return (
        *replaced,
        "packaging/honey/capability-profile.v1.json",
        "packaging/honey/artifact-matrix.v1.json",
        "packaging/honey/release-requirements.v1.json",
    )


def _expected_archive_paths(spec: ToolSpec) -> set[str]:
    common = {"RELEASE-METADATA.json", "README.md", "LICENSE", "NOTICE", "SHA256SUMS"}
    if spec.selector == "conformance":
        return common | {*CONFORMANCE_BINARIES, *CONFORMANCE_ASSETS}
    return common | {
        "bin/cigarbench",
        "bin/cigarbench-local-scale",
        "bin/cigarbench-performance",
        "bin/cigarbench-matrix",
        *BENCHMARK_ASSETS,
    }


def _load_configuration(root: Path, spec: ToolSpec) -> BuildConfiguration:
    root = root.resolve(strict=True)
    product = load_json(root / "packaging/product-version.v1.json")
    development_identity = (
        isinstance(product, dict)
        and product.get("release_state") == "development"
        and product.get("channel") == "development"
        and product.get("tag") is None
    )
    honey_identity = (
        isinstance(product, dict)
        and product.get("release_state") == "developer-preview"
        and product.get("channel") == "honey"
        and isinstance(product.get("version"), str)
        and product.get("tag") == f"v{product['version']}"
    )
    if (
        not isinstance(product, dict)
        or product.get("schema_version") != "cigar.product-version.v1"
        or not (development_identity or honey_identity)
        or product.get("prerelease") is not True
        or product.get("published") is not False
        or product.get("supported") is not False
        or not isinstance(product.get("version"), str)
        or product.get("context_abi") != "cigar.context.v1"
    ):
        raise ReleaseError(
            "product authority is not an unpublished development or Honey identity"
        )
    version = product["version"]
    context_abi = product["context_abi"]
    honey = bool(honey_identity)
    if honey and spec.selector != "conformance":
        raise ReleaseError(
            "Honey selects only the bounded conformance qualification tool"
        )
    authority = _authority_digests(root, spec, honey=honey)
    matrix_path = (
        "packaging/honey/artifact-matrix.v1.json"
        if honey
        else "packaging/artifact-matrix.v1.json"
    )
    profile_path = (
        "packaging/honey/capability-profile.v1.json"
        if honey
        else "packaging/development/local-macos-aarch64.v1.json"
    )
    matrix = load_json(root / matrix_path)
    profile = load_json(root / profile_path)
    contract_path = root.joinpath(*spec.contract_relative.split("/"))
    contract = load_json(contract_path)

    if honey:
        requirements = load_json(root / "packaging/honey/release-requirements.v1.json")
        internal = matrix.get("internal_inputs") if isinstance(matrix, dict) else None
        internal_rows = [
            row
            for row in internal or []
            if isinstance(row, dict) and row.get("id") == HONEY_INTERNAL_INPUT_ID
        ]
        identity = profile.get("identity") if isinstance(profile, dict) else None
        platform_profile = (
            profile.get("platform") if isinstance(profile, dict) else None
        )
        product_binding = (
            profile.get("product_version_binding")
            if isinstance(profile, dict)
            else None
        )
        mandatory_gates = (
            requirements.get("mandatory_gates")
            if isinstance(requirements, dict)
            else None
        )
        mandatory_gate_ids = (
            [row.get("id") for row in mandatory_gates if isinstance(row, dict)]
            if isinstance(mandatory_gates, list)
            else []
        )
        if (
            not isinstance(matrix, dict)
            or matrix.get("schema_version") != "cigar.honey.artifact-matrix.v1"
            or matrix.get("profile_id") != HONEY_PROFILE_ID
            or matrix.get("release_state") != "developer-preview"
            or matrix.get("product_version") != version
            or matrix.get("context_abi") != context_abi
            or matrix.get("fail_closed") is not True
            or internal_rows != [_honey_internal_input(spec, version)]
            or not isinstance(profile, dict)
            or profile.get("schema_version") != "cigar.honey.capability-profile.v1"
            or profile.get("profile_id") != HONEY_PROFILE_ID
            or profile.get("fail_closed") is not True
            or not isinstance(identity, dict)
            or identity.get("product_version") != version
            or identity.get("context_abi") != context_abi
            or identity.get("release_state") != "developer-preview"
            or identity.get("channel") != "honey"
            or identity.get("published") is not False
            or identity.get("supported") is not False
            or identity.get("production_qualified") is not False
            or platform_profile
            != {
                "deployment_modes": ["embedded", "local-sidecar"],
                "host_arch": "arm64",
                "host_os": "macos",
                "network_required": False,
                "target_triple": TARGET_TRIPLE,
                "trust_model": "single-local-os-user-with-explicit-agent-principals",
            }
            or product_binding
            != {
                "path": "packaging/product-version.v1.json",
                "sha256": authority["packaging/product-version.v1.json"]["sha256"],
            }
            or not isinstance(requirements, dict)
            or requirements.get("schema_version")
            != "cigar.honey.release-requirements.v1"
            or requirements.get("profile_id") != HONEY_PROFILE_ID
            or requirements.get("evidence_class") != "developer-preview"
            or requirements.get("fail_closed") is not True
            or requirements.get("required_source_state")
            != {"committed": True, "clean": True, "tagged_before_build": False}
            or not {
                "clean-committed-source",
                "conformance",
                "installed-runtime",
            }.issubset(mandatory_gate_ids)
        ):
            raise ReleaseError(
                "Honey qualification-tool internal input authority is incomplete or stale"
            )
    else:
        if (
            not isinstance(matrix, dict)
            or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
            or matrix.get("release_state") != "development"
            or matrix.get("product_version") != version
            or matrix.get("context_abi") != context_abi
            or not isinstance(matrix.get("artifacts"), list)
        ):
            raise ReleaseError("artifact matrix is stale relative to product authority")
        rows = [
            row
            for row in matrix["artifacts"]
            if isinstance(row, dict) and row.get("id") == spec.artifact_id
        ]
        expected_row = _matrix_row(spec, version)
        if rows != [expected_row]:
            raise ReleaseError(
                f"artifact matrix row is incomplete or stale: {spec.artifact_id}"
            )
        selected = (
            profile.get("selected_artifacts") if isinstance(profile, dict) else None
        )
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
            or selected_by_id.get(spec.artifact_id)
            != {
                "id": spec.artifact_id,
                "selection_group": spec.selection_group,
                "status": "planned",
                "built": False,
                "qualified": False,
            }
            or profile.get("missing_artifacts") != []
        ):
            raise ReleaseError(
                "development macOS profile does not keep the tool planned and unclaimed"
            )
    expected_paths = _expected_archive_paths(spec)
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id")
        != (
            "macos-conformance-runner-v1"
            if spec.selector == "conformance"
            else "macos-cigarbench-tool-v1"
        )
        or contract.get("formats") != ["tar.gz"]
        or set(contract.get("allow", [])) != expected_paths
        or set(contract.get("required", [])) != expected_paths
        or contract.get("checksum_manifest")
        != {"path": "SHA256SUMS", "scope": "all-payload-files"}
        or contract.get("version_binding")
        != {
            "path_pattern": "RELEASE-METADATA.json",
            "format": "json",
            "json_pointer": "/product_version",
        }
        or contract.get("abi_binding")
        != {
            "path_pattern": "RELEASE-METADATA.json",
            "format": "json",
            "json_pointer": "/context_abi",
        }
        or contract.get("symlinks") != "forbid"
        or contract.get("content_scan") is not True
    ):
        raise ReleaseError(
            f"package contract is incomplete or stale: {spec.contract_relative}"
        )

    source_assets = (
        CONFORMANCE_ASSETS if spec.selector == "conformance" else BENCHMARK_ASSETS
    )
    assets: dict[str, bytes] = {}
    for destination, relative in source_assets.items():
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, relative
        )
        if b"\r" in payload:
            raise ReleaseError(f"packaged source asset is not LF-only: {relative}")
        assets[destination] = payload
    for name in ("LICENSE", "NOTICE"):
        assets[name] = _read_stable_file(root / name, MAX_SOURCE_BYTES, name)
    return BuildConfiguration(
        root=root,
        spec=spec,
        version=version,
        context_abi=context_abi,
        filename=spec.filename_template.format(version=version),
        contract_path=contract_path,
        authority=authority,
        assets=assets,
        honey=honey,
    )


def _source_identity(
    root: Path, spec: ToolSpec, *, honey: bool = True
) -> dict[str, Any]:
    files = expand_files(root, _source_includes(spec, honey=honey), SOURCE_EXCLUDES)
    if not files:
        raise ReleaseError(f"{spec.selector} source inventory is empty")
    identity = git_state(root, tree_digest(files))
    if (
        identity.get("committed") is not True
        or not isinstance(identity.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", identity["revision"]) is None
        or not isinstance(identity.get("clean"), bool)
        or (honey and identity.get("clean") is not True)
        or not isinstance(identity.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None
    ):
        raise ReleaseError(
            "qualification-tool build requires a committed Git identity"
            + (" and Honey requires a clean tree" if honey else "")
        )
    return identity


def _secure_executable(value: Path | None, name: str) -> Path:
    supplied = value
    if supplied is None:
        discovered = shutil.which(name)
        if discovered is None:
            raise ReleaseError(f"required executable is unavailable: {name}")
        supplied = Path(discovered)
    if not supplied.is_absolute():
        raise ReleaseError(f"{name} executable path must be absolute")
    try:
        resolved = supplied.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {name} executable: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(supplied, os.X_OK)
    ):
        raise ReleaseError(f"{name} must resolve to an owner-controlled executable")
    return supplied


def _private_tool_directory(raw: str | None, fallback: Path, label: str) -> Path:
    selected = Path(raw).expanduser() if raw else fallback
    try:
        resolved = selected.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {label}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseError(f"{label} must be an owner-controlled directory")
    return resolved


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    label: str,
    maximum: int = MAX_COMMAND_OUTPUT,
) -> bytes:
    sandbox = _validated_macos_sandbox()
    try:
        result = run_bounded(
            [str(sandbox), "-p", MACOS_NO_EGRESS_POLICY, *command],
            cwd=cwd,
            env=environment,
            timeout=timeout,
            max_stdout=maximum,
            max_stderr=maximum,
        )
    except (OSError, subprocess.SubprocessError, ReleaseError) as error:
        raise ReleaseError(f"{label} could not run safely: {error}") from error
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, label))
    return result.stdout


def _validated_macos_sandbox() -> Path:
    """Return the fixed root-controlled Seatbelt launcher for tool subprocesses."""

    try:
        metadata = MACOS_SANDBOX_EXEC.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(
            "the fixed macOS no-egress sandbox launcher is unavailable"
        ) from error
    if (
        MACOS_SANDBOX_EXEC.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(MACOS_SANDBOX_EXEC, os.X_OK)
    ):
        raise ReleaseError(
            "the fixed macOS no-egress sandbox launcher is not root-controlled"
        )
    return MACOS_SANDBOX_EXEC


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    payload = _read_stable_file(
        path.resolve(strict=True), 64 * 1024 * 1024, f"{name} executable"
    )
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _cargo_environment(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    cargo: Path,
    rustc: Path,
    protoc: Path,
) -> dict[str, str]:
    target = scratch / "target"
    home = scratch / "home"
    temporary = scratch / "tmp"
    for directory in (target, home, temporary):
        directory.mkdir(mode=0o700)
    cargo_home = _private_tool_directory(
        os.environ.get("CARGO_HOME"), Path.home() / ".cargo", "CARGO_HOME"
    )
    rustup_home = _private_tool_directory(
        os.environ.get("RUSTUP_HOME"), Path.home() / ".rustup", "RUSTUP_HOME"
    )
    remaps = (
        (configuration.root, "/usr/src/cigar"),
        (scratch, "/usr/src/cigar-build"),
        (cargo_home, "/usr/src/cargo-home"),
        (rustup_home, "/usr/src/rustup-home"),
        (Path.home().resolve(strict=True), "/usr/src/owner-home"),
    )
    flags: list[str] = []
    seen: set[Path] = set()
    for source_path, destination in remaps:
        if source_path in seen:
            continue
        seen.add(source_path)
        flags.append(f"--remap-path-prefix={source_path}={destination}")
    path_entries: list[str] = []
    for directory in (
        cargo.parent,
        cargo.resolve(strict=True).parent,
        rustc.parent,
        rustc.resolve(strict=True).parent,
        protoc.parent,
        protoc.resolve(strict=True).parent,
        Path("/usr/bin"),
        Path("/bin"),
    ):
        value = str(directory)
        if value not in path_entries:
            path_entries.append(value)
    return {
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CIGAR_SOURCE_REVISION": str(source["revision"]),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "PATH": os.pathsep.join(path_entries),
        "PROTOC": str(protoc),
        "RUSTC": str(rustc),
        "RUSTUP_HOME": str(rustup_home),
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "ZERO_AR_DATE": "1",
    }


def _validate_macho_arm64(payload: bytes, label: str) -> None:
    if not 32 <= len(payload) <= MAX_BINARY_BYTES:
        raise ReleaseError(f"{label} is outside the bounded executable size")
    try:
        magic, cpu_type, cpu_subtype, file_type = struct.unpack("<IIII", payload[:16])
    except struct.error as error:
        raise ReleaseError(f"{label} has a truncated Mach-O header") from error
    if (
        magic != 0xFEEDFACF
        or cpu_type != 0x0100000C
        or cpu_subtype != 0
        or file_type != 2
    ):
        raise ReleaseError(f"{label} is not a thin arm64 macOS executable")


def _build_conformance(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltTool:
    cargo = _secure_executable(arguments.cargo, "cargo")
    rustc = _secure_executable(arguments.rustc, "rustc")
    protoc = _secure_executable(arguments.protoc, "protoc")
    environment = _cargo_environment(
        configuration, source, epoch, scratch, cargo, rustc, protoc
    )
    rustc_identity = _run_checked(
        [str(rustc), "-vV"],
        cwd=configuration.root,
        environment=environment,
        timeout=30,
        label="rustc identity",
        maximum=256 * 1024,
    ).decode("utf-8", errors="strict")
    cargo_identity = (
        _run_checked(
            [str(cargo), "-V"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="cargo identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    protoc_identity = (
        _run_checked(
            [str(protoc), "--version"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="protoc identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if f"host: {TARGET_TRIPLE}" not in rustc_identity:
        raise ReleaseError("rustc host is not native aarch64-apple-darwin")
    _run_checked(
        [
            str(cargo),
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            TARGET_TRIPLE,
            "-p",
            "cigar-conformance",
            "--bins",
        ],
        cwd=configuration.root,
        environment=environment,
        timeout=1_800,
        label="native conformance-runner build",
    )
    binary_path = scratch / "target" / TARGET_TRIPLE / "release" / "cigar-conformance"
    binary = _read_stable_file(binary_path, MAX_BINARY_BYTES, "built cigar-conformance")
    _validate_macho_arm64(binary, "cigar-conformance")
    qualifier_path = (
        scratch / "target" / TARGET_TRIPLE / "release" / "cigar-install-qualifier"
    )
    qualifier = _read_stable_file(
        qualifier_path,
        MAX_BINARY_BYTES,
        "built cigar-install-qualifier",
    )
    _validate_macho_arm64(qualifier, "cigar-install-qualifier")
    runtime_environment = {
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(scratch / "tmp"),
        "TZ": "UTC",
    }
    help_output = _run_checked(
        [str(binary_path), "--help"],
        cwd=scratch,
        environment=runtime_environment,
        timeout=30,
        label="conformance runner invocation probe",
        maximum=256 * 1024,
    )
    if (
        b"cigar-conformance run" not in help_output
        or b"cigar-conformance verify" not in help_output
    ):
        raise ReleaseError("conformance runner help surface is stale")
    qualifier_help = _run_checked(
        [str(qualifier_path), "--help"],
        cwd=scratch,
        environment=runtime_environment,
        timeout=30,
        label="install qualifier invocation probe",
        maximum=256 * 1024,
    )
    if (
        b"Usage: cigar-install-qualifier" not in qualifier_help
        or b"--artifact-sha256" not in qualifier_help
        or b"--context-abi cigar.context.v1" not in qualifier_help
        or b"--source-revision <git-object-id>" not in qualifier_help
        or b"--sandbox-root <absolute-path>" not in qualifier_help
        or b"--candidate-input-root <absolute-path>" not in qualifier_help
    ):
        raise ReleaseError("install qualifier help surface is stale")
    entries = (
        PackageEntry("README.md", CONFORMANCE_README, 0o644),
        PackageEntry("LICENSE", configuration.assets["LICENSE"], 0o644),
        PackageEntry("NOTICE", configuration.assets["NOTICE"], 0o644),
        PackageEntry("bin/cigar-conformance", binary, 0o755),
        PackageEntry("bin/cigar-install-qualifier", qualifier, 0o755),
        *(
            PackageEntry(path, payload, 0o644)
            for path, payload in sorted(
                configuration.assets.items(), key=lambda item: item[0].encode("utf-8")
            )
            if path not in {"LICENSE", "NOTICE"}
        ),
    )
    return BuiltTool(
        entries=entries,
        tools=(
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(protoc, "protoc", protoc_identity),
            _tool_record(rustc, "rustc", rustc_identity.strip()),
        ),
        invocation_probes=(
            {
                "command": "bin/cigar-conformance --help",
                "status": "passed",
                "scope": "invocation-only",
                "qualifying_evidence": False,
            },
            {
                "command": "bin/cigar-install-qualifier --help",
                "status": "passed",
                "scope": "invocation-only",
                "qualifying_evidence": False,
            },
        ),
    )


def _write_stage(root: Path, entries: tuple[PackageEntry, ...]) -> None:
    for entry in entries:
        path = root.joinpath(*safe_relative_path(entry.path).split("/"))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, entry.mode)
        try:
            written = 0
            while written < len(entry.payload):
                written += os.write(descriptor, entry.payload[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, entry.mode)


def _build_cigarbench(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltTool:
    cargo = _secure_executable(arguments.cargo, "cargo")
    rustc = _secure_executable(arguments.rustc, "rustc")
    protoc = _secure_executable(arguments.protoc, "protoc")
    cargo_environment = _cargo_environment(
        configuration, source, epoch, scratch, cargo, rustc, protoc
    )
    rustc_identity = _run_checked(
        [str(rustc), "-vV"],
        cwd=configuration.root,
        environment=cargo_environment,
        timeout=30,
        label="rustc identity",
        maximum=256 * 1024,
    ).decode("utf-8", errors="strict")
    cargo_identity = (
        _run_checked(
            [str(cargo), "-V"],
            cwd=configuration.root,
            environment=cargo_environment,
            timeout=30,
            label="cargo identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    protoc_identity = (
        _run_checked(
            [str(protoc), "--version"],
            cwd=configuration.root,
            environment=cargo_environment,
            timeout=30,
            label="protoc identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if f"host: {TARGET_TRIPLE}" not in rustc_identity:
        raise ReleaseError("rustc host is not native aarch64-apple-darwin")
    driver_manifest = (
        configuration.root / "benches/cigarbench/local_scale_driver/Cargo.toml"
    )
    _run_checked(
        [
            str(cargo),
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            TARGET_TRIPLE,
            "--manifest-path",
            str(driver_manifest),
        ],
        cwd=configuration.root,
        environment=cargo_environment,
        timeout=1_800,
        label="native local-scale driver build",
    )
    driver_path = (
        scratch / "target" / TARGET_TRIPLE / "release" / "cigar-local-scale-driver"
    )
    driver = _read_stable_file(
        driver_path, MAX_BINARY_BYTES, "built cigar-local-scale-driver"
    )
    _validate_macho_arm64(driver, "cigar-local-scale-driver")
    python = _secure_executable(
        Path(FIXED_CIGARBENCH_PYTHON), "fixed CIGARBench python3"
    )
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(scratch),
        "TZ": "UTC",
    }
    python_identity = (
        _run_checked(
            [str(python), "-B", "-I", "-S", "--version"],
            cwd=scratch,
            environment=environment,
            timeout=30,
            label="Python identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    version_probe = (
        _run_checked(
            [
                str(python),
                "-B",
                "-I",
                "-S",
                "-c",
                "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
            ],
            cwd=scratch,
            environment=environment,
            timeout=30,
            label="Python compatibility probe",
            maximum=256 * 1024,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)", version_probe)
    if match is None or (int(match.group(1)), int(match.group(2))) < (3, 11):
        raise ReleaseError("CIGARBench requires Python 3.11 or newer")
    entries = (
        PackageEntry("README.md", BENCHMARK_README, 0o644),
        PackageEntry("LICENSE", configuration.assets["LICENSE"], 0o644),
        PackageEntry("NOTICE", configuration.assets["NOTICE"], 0o644),
        PackageEntry("bin/cigarbench", _launcher_bytes(), 0o755),
        PackageEntry("bin/cigarbench-local-scale", driver, 0o755),
        PackageEntry("bin/cigarbench-performance", _launcher_bytes(), 0o755),
        PackageEntry("bin/cigarbench-matrix", _launcher_bytes(), 0o755),
        *(
            PackageEntry(path, payload, 0o644)
            for path, payload in sorted(
                configuration.assets.items(), key=lambda item: item[0].encode("utf-8")
            )
            if path not in {"LICENSE", "NOTICE"}
        ),
    )
    install = scratch / "install"
    install.mkdir(mode=0o700)
    _write_stage(install, entries)
    hostile = scratch / "hostile"
    hostile_path = hostile / "path"
    hostile_user = hostile / "user"
    hostile_path.mkdir(parents=True, mode=0o700)
    user_site = hostile_user / f"lib/python{version_probe}/site-packages"
    user_site.mkdir(parents=True, mode=0o700)
    markers = {
        "pythonpath": hostile / "pythonpath-loaded",
        "user-site": hostile / "user-site-loaded",
        "cwd": hostile / "cwd-loaded",
        "startup": hostile / "startup-loaded",
        "shell": hostile / "shell-loaded",
    }

    def hostile_payload(marker: Path) -> bytes:
        return f"open({str(marker)!r}, 'w', encoding='utf-8').write('loaded')\n".encode(
            "utf-8"
        )

    _write_stage(
        hostile_path,
        (
            PackageEntry(
                "sitecustomize.py", hostile_payload(markers["pythonpath"]), 0o644
            ),
        ),
    )
    _write_stage(
        user_site,
        (
            PackageEntry(
                "usercustomize.py", hostile_payload(markers["user-site"]), 0o644
            ),
        ),
    )
    _write_stage(
        install,
        (PackageEntry("json.py", hostile_payload(markers["cwd"]), 0o644),),
    )
    startup = hostile / "startup.py"
    shell_startup = hostile / "shell-startup.sh"
    _write_stage(
        hostile,
        (
            PackageEntry("startup.py", hostile_payload(markers["startup"]), 0o644),
            PackageEntry(
                "shell-startup.sh",
                f"printf loaded > {str(markers['shell'])!r}\n".encode("utf-8"),
                0o644,
            ),
        ),
    )
    hostile_environment = {
        **environment,
        "BASH_ENV": str(shell_startup),
        "CDPATH": str(hostile),
        "ENV": str(shell_startup),
        "HOME": str(hostile_user),
        "PATH": str(hostile_path),
        "PYTHONBREAKPOINT": "hostile.breakpoint",
        "PYTHONDONTWRITEBYTECODE": "0",
        "PYTHONHOME": str(hostile / "invalid-home"),
        "PYTHONINSPECT": "1",
        "PYTHONPATH": str(hostile_path),
        "PYTHONSAFEPATH": "0",
        "PYTHONSTARTUP": str(startup),
        "PYTHONUSERBASE": str(hostile_user),
        "PYTHONWARNINGS": "error",
    }
    probes: list[dict[str, object]] = []
    for name in ("cigarbench", "cigarbench-performance", "cigarbench-matrix"):
        output = _run_checked(
            [str(install / "bin" / name), "--help"],
            cwd=install,
            environment=hostile_environment,
            timeout=30,
            label=f"{name} launcher invocation probe",
            maximum=1024 * 1024,
        )
        if b"usage:" not in output:
            raise ReleaseError(f"{name} help surface is stale")
        probes.append(
            {
                "command": f"bin/{name} --help",
                "status": "passed",
                "scope": "invocation-only",
                "direct_installed_launcher": True,
                "python_injection_resistance": "passed",
                "qualifying_evidence": False,
            }
        )
    loaded = [name for name, marker in markers.items() if marker.exists()]
    if loaded:
        raise ReleaseError(
            "CIGARBench launcher admitted hostile startup state: " + ", ".join(loaded)
        )
    driver_help = _run_checked(
        [str(install / "bin/cigarbench-local-scale"), "--help"],
        cwd=install,
        environment=environment,
        timeout=30,
        label="cigarbench-local-scale invocation probe",
        maximum=1024 * 1024,
    )
    if (
        b"Usage: cigar-local-scale-driver" not in driver_help
        or b"1,000,000-atom / 10,000,000-edge / 1,600 x 64-MiB" not in driver_help
        or b"prepare-fixture" in driver_help
        or b"fixture-run" in driver_help
    ):
        raise ReleaseError("native local-scale driver help surface is stale")
    probes.append(
        {
            "command": "bin/cigarbench-local-scale --help",
            "status": "passed",
            "scope": "invocation-only",
            "direct_installed_launcher": True,
            "python_injection_resistance": "not-applicable-native-binary",
            "qualifying_evidence": False,
        }
    )
    python_record = _tool_record(python, "python3", python_identity)
    python_record["invocation_path"] = FIXED_CIGARBENCH_PYTHON
    python_record["isolated_flags"] = ["-B", "-I", "-S"]
    return BuiltTool(
        entries=entries,
        tools=(
            python_record,
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(protoc, "protoc", protoc_identity),
            _tool_record(rustc, "rustc", rustc_identity.strip()),
        ),
        invocation_probes=tuple(probes),
    )


def _payload_tree(entries: list[PackageEntry]) -> str:
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


def _validate_entries(entries: list[PackageEntry]) -> None:
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        name = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", name).casefold()
        if name in names or alias in aliases:
            raise ReleaseError(f"duplicate or portable-colliding package path: {name}")
        if entry.mode not in {0o644, 0o755} or not entry.payload:
            raise ReleaseError(
                f"package entry has invalid mode or empty payload: {name}"
            )
        names.add(name)
        aliases.add(alias)


def _package_entries(tool: BuiltTool) -> list[PackageEntry]:
    base = list(tool.entries)
    checksums = "".join(
        f"{sha256_bytes(entry.payload)}  {entry.path}\n"
        for entry in sorted(base, key=lambda item: item.path.encode("utf-8"))
    ).encode("ascii")
    return [*base, PackageEntry("SHA256SUMS", checksums, 0o644)]


def _write_archive(
    path: Path,
    entries: list[PackageEntry],
    metadata: dict[str, Any],
    epoch: int,
) -> None:
    complete = [
        PackageEntry("RELEASE-METADATA.json", canonical_json_bytes(metadata), 0o644),
        *entries,
    ]
    _validate_entries(complete)
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged archive: {path}")
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
                        complete, key=lambda item: item.path.encode("utf-8")
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


def produce(
    arguments: argparse.Namespace,
    *,
    tool_builder: ToolBuilder | None = None,
) -> dict[str, Any]:
    spec = SPECS[arguments.tool]
    builder = tool_builder or (
        _build_conformance if spec.selector == "conformance" else _build_cigarbench
    )
    root = arguments.root.resolve(strict=True)
    host = _require_host()
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    configuration = _load_configuration(root, spec)
    source_before = _source_identity(root, spec, honey=configuration.honey)
    if configuration.honey and source_before.get("clean") is not True:
        raise ReleaseError(
            "qualification-tool build requires a committed Git identity and Honey requires a clean tree"
        )
    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(
            prefix=f"cigar-{spec.selector}-package-"
        ) as raw:
            scratch = Path(raw).resolve(strict=True)
            # Qualification-tool staging contains unpublished executable bytes.
            # 0700 is the intended least-privilege mode, not a permissive default.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                scratch, 0o700
            )
            tool = builder(configuration, source_before, epoch, scratch, arguments)
            if not tool.entries or not tool.tools or not tool.invocation_probes:
                raise ReleaseError("qualification-tool build result is incomplete")
            if spec.selector == "conformance":
                binaries = {
                    entry.path: entry
                    for entry in tool.entries
                    if entry.path in CONFORMANCE_BINARIES
                }
                if set(binaries) != set(CONFORMANCE_BINARIES):
                    raise ReleaseError(
                        "conformance build did not produce the exact native tool set"
                    )
                for relative in CONFORMANCE_BINARIES:
                    _validate_macho_arm64(
                        binaries[relative].payload,
                        relative.removeprefix("bin/"),
                    )
            if _source_identity(root, spec, honey=configuration.honey) != source_before:
                raise ReleaseError(
                    "qualification-tool source changed during construction"
                )
            if (
                _authority_digests(root, spec, honey=configuration.honey)
                != configuration.authority
            ):
                raise ReleaseError(
                    "qualification-tool authority changed during construction"
                )
            entries = _package_entries(tool)
            contract_sha256 = str(
                configuration.authority[spec.contract_relative]["sha256"]
            )
            metadata = {
                "schema_version": "cigar.release-metadata.v1",
                "artifact_id": spec.artifact_id,
                "product_version": configuration.version,
                "context_abi": configuration.context_abi,
                "source_date_epoch": epoch,
                "source": source_before,
                "input_tree_sha256": _payload_tree(entries),
                "input_file_count": len(entries),
                "contract": spec.contract_relative,
                "contract_sha256": contract_sha256,
            }
            staged_archive = scratch / configuration.filename
            _write_archive(staged_archive, entries, metadata, epoch)
            archive_bytes = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "staged qualification-tool archive"
            )
            archive_sha256 = sha256_bytes(archive_bytes)
            verification = verify_package(
                staged_archive,
                configuration.contract_path,
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            if _source_identity(root, spec, honey=configuration.honey) != source_before:
                raise ReleaseError(
                    "qualification-tool source changed during verification"
                )
            if (
                _authority_digests(root, spec, honey=configuration.honey)
                != configuration.authority
            ):
                raise ReleaseError(
                    "qualification-tool authority changed during verification"
                )
            verified = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified qualification-tool archive"
            )
            if (
                len(verified) != len(archive_bytes)
                or sha256_bytes(verified) != archive_sha256
            ):
                raise ReleaseError(
                    "qualification-tool archive changed during verification"
                )
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=archive_sha256,
                expected_bytes=len(archive_bytes),
            )
        receipt = {
            "schema_version": "cigar.development-qualification-tool-build.v1",
            "status": "built-unqualified",
            "artifact_id": spec.artifact_id,
            "target": TARGET_TRIPLE,
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": epoch,
            "source": source_before,
            "host": host,
            "archive": archive_reference.as_dict(),
            "install_target": spec.install_target,
            "contract": {
                "path": spec.contract_relative,
                "sha256": contract_sha256,
            },
            "authority": configuration.authority,
            "build_tools": list(tool.tools),
            "build_environment": {
                "network_enforcement": MACOS_NO_EGRESS_ENFORCEMENT,
                "sandbox_launcher": str(MACOS_SANDBOX_EXEC),
                "sandbox_policy": MACOS_NO_EGRESS_POLICY,
            },
            "invocation_probes": list(tool.invocation_probes),
            "payload": {
                entry.path: {
                    "sha256": sha256_bytes(entry.payload),
                    "bytes": len(entry.payload),
                    "mode": f"{entry.mode:04o}",
                }
                for entry in entries
            },
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "claims": {
                "development_build": not configuration.honey,
                **({"developer_preview_build": True} if configuration.honey else {}),
                "candidate": False,
                "distribution_signed": False,
                "notarized": False,
                "installed_qualified": False,
                "conformance_qualified": False,
                "benchmark_efficacy": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }
        workspace.write_json(spec.receipt_name, receipt)
        workspace.read_files(
            {configuration.filename, spec.receipt_name}, strict_read_only=True
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
    except (EvidenceWorkspaceError, KeyError, OSError, ReleaseError) as error:
        raise SystemExit(f"macOS qualification-tool build failed: {error}") from error
