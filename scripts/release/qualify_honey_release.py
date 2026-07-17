#!/usr/bin/env python3
"""Build and qualify the bounded CIGAR Honey developer preview.

This orchestration never tags, uploads, or publishes. ``build`` creates the
exact artifact workspaces and 13-file candidate from one clean commit.
``qualify`` must run as a standard non-admin macOS user and creates private
installed/evidence results. ``verify`` non-mutatingly reconstructs both the
public integrity result and private evidence ledger.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
from typing import Any, Sequence

import build_honey_evidence as honey_evidence
from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    run_bounded,
    safe_relative_path,
    sha256_file,
)
from source_descriptor import SourceDescriptorError, build_source_descriptor
from verify_honey_release import verify as verify_public_candidate


VERSION = "0.9.0-honey.1"
ABI = "cigar.context.v1"
TARGET = "aarch64-apple-darwin"
RUNTIME_NAME = f"cigar-{VERSION}-{TARGET}.tar.gz"
TOOL_NAME = f"cigar-conformance-{VERSION}-{TARGET}.tar.gz"
TYPESCRIPT_NAME = f"cigar-sdk-{VERSION}.tgz"
PYTHON_WHEEL_NAME = "cigar_sdk-0.9.0.dev1-py3-none-any.whl"
PYTHON_SDIST_NAME = "cigar_sdk-0.9.0.dev1.tar.gz"
RUST_NAME = f"cigar-rust-sdk-{VERSION}-local-registry.tar.gz"
CLAUDE_NAME = f"cigar-claude-code-{VERSION}.tar.gz"
DEMO_NAME = f"cigar-honey-demos-{VERSION}.tar.gz"
QUALIFICATION_RESULT = "honey-qualification-result.json"

POLICY_INPUTS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
    "packaging/honey/capability-ownership.v1.json",
    "packaging/honey/local-archives.v1.json",
    "packaging/honey/schemas/honey-evidence.v1.schema.json",
    "packaging/honey/contracts/source-archive.v1.json",
    "packaging/honey/contracts/docs-archive.v1.json",
    "packaging/honey/contracts/schemas-conformance.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    "packaging/contracts/macos-conformance-runner.v1.json",
    "packaging/contracts/npm-package.v1.json",
    "packaging/contracts/python-wheel.v1.json",
    "packaging/contracts/python-sdist.v1.json",
    "packaging/honey/contracts/rust-sdk-local-registry.v1.json",
    "packaging/contracts/plugin-archive.v1.json",
    "packaging/honey/contracts/demos-archive.v1.json",
)
TOOL_INPUTS = (
    "scripts/release/build_archives.py",
    "scripts/release/build_macos_aarch64_archive.py",
    "scripts/release/build_macos_qualification_tools.py",
    "scripts/release/build_typescript_sdk.py",
    "scripts/release/build_python_sdk_artifacts.py",
    "scripts/release/build_rust_sdk_crate.py",
    "scripts/release/build_claude_code_plugin.py",
    "scripts/release/build_honey_demos.py",
    "scripts/release/assemble_honey_release.py",
    "scripts/release/verify_honey_release.py",
    "scripts/release/qualify_install.py",
    "scripts/release/qualify_claude_code_plugin.py",
    "scripts/release/qualify_honey_docs.py",
    "scripts/release/build_honey_gate_reports.py",
    "scripts/release/build_honey_evidence.py",
    "scripts/release/qualify_honey_release.py",
    "demos/run_honey.py",
    "scripts/release/check_docs.py",
)


class HoneyQualificationError(ReleaseError):
    """The exact Honey build/qualification pipeline cannot proceed."""


@dataclass(frozen=True)
class Layout:
    root: Path

    @property
    def portable_container(self) -> Path:
        return self.root / "portable"

    @property
    def portable(self) -> Path:
        return self.portable_container / "payload"

    def path(self, name: str) -> Path:
        return self.root / name

    @property
    def native(self) -> Path:
        return self.path("native")

    @property
    def tools(self) -> Path:
        return self.path("qualification-tools")

    @property
    def typescript(self) -> Path:
        return self.path("typescript")

    @property
    def python(self) -> Path:
        return self.path("python")

    @property
    def rust(self) -> Path:
        return self.path("rust")

    @property
    def claude(self) -> Path:
        return self.path("claude")

    @property
    def demos(self) -> Path:
        return self.path("demos")

    @property
    def candidate(self) -> Path:
        return self.path("candidate")

    @property
    def source(self) -> Path:
        return self.path("source")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("build", help="build the exact unqualified candidate")
    subparsers.add_parser(
        "qualify", help="run standard-user installed gates and create evidence"
    )
    subparsers.add_parser("verify", help="non-mutating public and private verification")
    subparsers.add_parser("all", help="build then qualify; never publish")
    return parser


def parse_arguments() -> argparse.Namespace:
    return _parser().parse_args()


def _run(
    root: Path,
    command: Sequence[str],
    *,
    environment: dict[str, str],
    label: str,
    timeout: int = 1_800,
) -> bytes:
    print(f"honey: {label}", file=sys.stderr, flush=True)
    result = run_bounded(
        list(command),
        cwd=root,
        env=environment,
        timeout=timeout,
        max_stdout=64 * 1024 * 1024,
        max_stderr=64 * 1024 * 1024,
    )
    if result.returncode != 0:
        raise HoneyQualificationError(
            f"{label} failed: exit={result.returncode} "
            f"stdout_sha256={hashlib.sha256(result.stdout).hexdigest()} "
            f"stderr_sha256={hashlib.sha256(result.stderr).hexdigest()}"
        )
    return result.stdout


def _git(root: Path, *arguments: str) -> bytes:
    result = run_bounded(
        ["git", "--no-replace-objects", *arguments],
        cwd=root,
        timeout=60,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if result.returncode != 0:
        raise HoneyQualificationError("cannot inspect the candidate Git tree")
    return result.stdout


def _source_identity(root: Path) -> tuple[str, str]:
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise HoneyQualificationError("Honey orchestration requires a clean Git tree")
    revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    return revision, tree


def _epoch(root: Path, supplied: int | None) -> int:
    raw = _git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip()
    try:
        commit_epoch = int(raw)
    except ValueError as error:
        raise HoneyQualificationError("candidate commit epoch is invalid") from error
    if supplied is not None and supplied != commit_epoch:
        raise HoneyQualificationError(
            "SOURCE_DATE_EPOCH must equal the exact candidate commit timestamp"
        )
    return commit_epoch


def _environment(epoch: int) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    environment.update(
        {
            "SOURCE_DATE_EPOCH": str(epoch),
            "CARGO_NET_OFFLINE": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NPM_CONFIG_OFFLINE": "true",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "UV_OFFLINE": "1",
        }
    )
    return environment


def _external_root(path: Path, repository: Path, *, create: bool) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise HoneyQualificationError("evidence root must be absolute and canonical")
    if sys.platform == "darwin" and not os.fspath(path).startswith("/private/tmp/"):
        raise HoneyQualificationError(
            "macOS Honey evidence must live under /private/tmp"
        )
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise HoneyQualificationError(
                "evidence root parent must be an existing canonical directory"
            )
    except OSError as error:
        raise HoneyQualificationError(
            "evidence root parent must be an existing canonical directory"
        ) from error
    try:
        inside = os.path.commonpath(
            (os.fspath(path), os.fspath(repository))
        ) == os.fspath(repository)
    except ValueError:
        inside = False
    if inside:
        raise HoneyQualificationError("evidence root must be outside the repository")
    if create:
        if path.exists() or path.is_symlink():
            raise HoneyQualificationError("build evidence root must be create-new")
        path.mkdir(mode=0o700, parents=False)
    resolved = path.resolve(strict=True)
    metadata = path.stat(follow_symlinks=False)
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HoneyQualificationError(
            "evidence root is not canonical and owner-private"
        )
    return path


def _write_source_descriptor(root: Path, layout: Layout, epoch: int) -> dict[str, Any]:
    archive = layout.portable / f"cigar-{VERSION}-source.tar.gz"
    generated_at = datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    descriptor = build_source_descriptor(
        repository_root=root,
        generated_at=generated_at,
        source_archive={
            "name": archive.name,
            "sha256": sha256_file(archive),
            "bytes": archive.stat().st_size,
        },
        policy_inputs=POLICY_INPUTS,
        tool_inputs=TOOL_INPUTS,
        require_clean=True,
    )
    with EvidenceWorkspace.create(layout.source, repository_root=root) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        workspace.write_json("source-descriptor.json", descriptor)
        workspace.read_files({"source-descriptor.json"}, strict_read_only=True)
    return descriptor


def _build(root: Path, layout: Layout, epoch: int) -> dict[str, Any]:
    before = _source_identity(root)
    environment = _environment(epoch)
    python = sys.executable
    _run(
        root,
        [
            python,
            "scripts/release/build_archives.py",
            "--manifest",
            "packaging/honey/local-archives.v1.json",
            "--evidence-dir",
            os.fspath(layout.portable_container),
            "--out",
            "payload",
            "--source-date-epoch",
            str(epoch),
            "--require-committed-clean",
        ],
        environment=environment,
        label="portable archives",
    )
    descriptor = _write_source_descriptor(root, layout, epoch)
    producer_commands = (
        (
            "native runtime",
            [
                python,
                "scripts/release/build_macos_aarch64_archive.py",
                "--evidence-dir",
                os.fspath(layout.native),
                "--source-date-epoch",
                str(epoch),
            ],
        ),
        (
            "qualification tools",
            [
                python,
                "scripts/release/build_macos_qualification_tools.py",
                "conformance",
                "--evidence-dir",
                os.fspath(layout.tools),
                "--source-date-epoch",
                str(epoch),
            ],
        ),
        (
            "TypeScript SDK",
            [
                python,
                "scripts/release/build_typescript_sdk.py",
                "--evidence-dir",
                os.fspath(layout.typescript),
                "--source-date-epoch",
                str(epoch),
            ],
        ),
        (
            "Python SDK",
            [
                python,
                "scripts/release/build_python_sdk_artifacts.py",
                "--evidence-dir",
                os.fspath(layout.python),
                "--source-date-epoch",
                str(epoch),
            ],
        ),
        (
            "Rust SDK local registry",
            [
                python,
                "scripts/release/build_rust_sdk_crate.py",
                "--honey-local-registry-kit",
                "--evidence-dir",
                os.fspath(layout.rust),
                "--source-date-epoch",
                str(epoch),
            ],
        ),
    )
    for label, command in producer_commands:
        _run(root, command, environment=environment, label=label)
    _run(
        root,
        [
            python,
            "scripts/release/build_claude_code_plugin.py",
            "--runtime-archive",
            os.fspath(layout.native / RUNTIME_NAME),
            "--evidence-dir",
            os.fspath(layout.claude),
            "--source-date-epoch",
            str(epoch),
        ],
        environment=environment,
        label="Claude Code plugin",
    )
    _run(
        root,
        [
            python,
            "scripts/release/build_honey_demos.py",
            "--evidence-dir",
            os.fspath(layout.demos),
            "--source-date-epoch",
            str(epoch),
        ],
        environment=environment,
        label="Honey demos",
    )
    assembly = [
        python,
        "scripts/release/assemble_honey_release.py",
        "--source-date-epoch",
        str(epoch),
        "--evidence-dir",
        os.fspath(layout.candidate),
    ]
    for name, path in (
        ("portable", layout.portable),
        ("native", layout.native),
        ("typescript", layout.typescript),
        ("python", layout.python),
        ("rust", layout.rust),
        ("claude", layout.claude),
        ("demos", layout.demos),
    ):
        assembly.extend(("--workspace", f"{name}={path}"))
    _run(root, assembly, environment=environment, label="Honey assembly")
    verification = verify_public_candidate(layout.candidate, root)
    if verification.get("status") != "passed-artifact-integrity":
        raise HoneyQualificationError("assembled candidate failed public verification")
    if _source_identity(root) != before:
        raise HoneyQualificationError("source changed while building Honey")
    return {
        "schema_version": "cigar.honey.build-result.v1",
        "status": "built-unqualified",
        "version": VERSION,
        "source_revision": descriptor["git"]["revision"],
        "source_tree": descriptor["git"]["tree"],
        "candidate_manifest_sha256": sha256_file(
            layout.candidate / "honey-release-manifest.json"
        ),
        "qualification_required": True,
    }


def _copy_static_reports(root: Path, layout: Layout) -> Path:
    destination = layout.path("static-reports")
    files = {
        "conformance-result.v1.json": root / "reports/conformance-result.v1.json",
        "third-party-license-inventory.v1.json": root
        / "packaging/licenses/third-party-inventory.v1.json",
    }
    with EvidenceWorkspace.create(destination, repository_root=root) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        for name, source in files.items():
            workspace.attach_file(
                source,
                name,
                expected_sha256=sha256_file(source),
                expected_bytes=source.stat().st_size,
            )
        workspace.read_files(set(files), strict_read_only=True)
    return destination


def _artifact_rows(layout: Layout, matrix: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": row["id"], "workspace": "candidate", "path": row["filename"]}
        for row in matrix["artifacts"]
    ]


def _evidence_rows(
    root: Path, layout: Layout, gate_reports: Path, static_reports: Path
) -> list[dict[str, Any]]:
    profile = load_json(root / "packaging/honey/capability-profile.v1.json")
    capabilities = sorted(row["id"] for row in profile["capabilities"])
    locations: dict[str, tuple[str, str]] = {
        "bounded-safety-report": ("gate-reports", "bounded-safety-report.json"),
        "claude-lifecycle-report": (
            "claude-qualification",
            "claude-code-plugin-installed-development-qualification.json",
        ),
        "documentation-report": ("docs-report", "documentation-report.json"),
        "installed-runtime-report": ("installed", "installed-runtime-report.json"),
        "license-inventory": (
            "static-reports",
            "third-party-license-inventory.v1.json",
        ),
        "offline-dependency-check": (
            "gate-reports",
            "offline-dependency-check.json",
        ),
        "other-demo-reports": ("demo-other", "other-demo-report.json"),
        "python-clean-install": ("python", "python-sdk-build-receipt.json"),
        "qualification-tools": (
            "static-reports",
            "conformance-result.v1.json",
        ),
        "rust-clean-consumer": (
            "rust",
            "rust-sdk-local-registry-build-receipt.json",
        ),
        "secret-scan": ("gate-reports", "secret-scan.json"),
        "two-agent-demo-report": ("demo-two-agent", "two-agent-demo-report.json"),
        "typescript-clean-install": (
            "typescript",
            "typescript-sdk-build-receipt.json",
        ),
    }
    tools: dict[str, dict[str, Any] | None] = {
        identifier: None for identifier in honey_evidence.REQUIRED_EVIDENCE
    }
    for identifier, filename in (
        ("bounded-safety-report", "bounded-safety-report.json"),
        ("offline-dependency-check", "offline-dependency-check.json"),
        ("secret-scan", "secret-scan.json"),
    ):
        tools[identifier] = load_json(gate_reports / filename).get("tool")
    tools["license-inventory"] = {
        "name": "generate_license_inventory.py",
        "version": "1",
        "database_updated_at": None,
        "database_freshness": "not-applicable",
        "offline": True,
    }
    capability_policy: dict[str, list[str]] = {
        "bounded-safety-report": capabilities,
        "claude-lifecycle-report": ["claude-code", "mcp"],
        "documentation-report": ["cli"],
        "installed-runtime-report": capabilities,
        "license-inventory": ["cli"],
        "offline-dependency-check": ["python-sdk", "rust-sdk", "typescript-sdk"],
        "other-demo-reports": [
            "claude-code",
            "governed-context",
            "observational-replay",
            "recoverable-effects",
        ],
        "python-clean-install": ["python-sdk"],
        "qualification-tools": ["governed-context"],
        "rust-clean-consumer": ["rust-sdk"],
        "secret-scan": ["policy-enforcement"],
        "two-agent-demo-report": ["two-agent-handoff"],
        "typescript-clean-install": ["typescript-sdk"],
    }
    del root, layout, static_reports
    rows = []
    for identifier in sorted(honey_evidence.REQUIRED_EVIDENCE):
        workspace, path = locations[identifier]
        rows.append(
            {
                "id": identifier,
                "category": honey_evidence.REQUIRED_EVIDENCE[identifier],
                "workspace": workspace,
                "path": path,
                "schema_version": honey_evidence.ACCEPTED_REPORT_SCHEMAS[identifier],
                "artifact_ids": sorted(
                    honey_evidence.EVIDENCE_ARTIFACT_POLICY[identifier]
                ),
                "capability_ids": sorted(capability_policy[identifier]),
                "mandatory_gate_ids": sorted(
                    honey_evidence.EVIDENCE_GATE_POLICY[identifier]
                ),
                "tool": tools[identifier],
            }
        )
    return rows


def _workspace_arguments(layout: Layout) -> list[str]:
    pairs = (
        ("candidate", layout.candidate),
        ("source", layout.source),
        ("installed", layout.path("installed")),
        ("typescript", layout.typescript),
        ("python", layout.python),
        ("rust", layout.rust),
        ("claude-qualification", layout.path("claude-qualification")),
        ("demo-two-agent", layout.path("demo-two-agent")),
        ("demo-other", layout.path("demo-other")),
        ("docs-report", layout.path("docs-report")),
        ("gate-reports", layout.path("gate-reports")),
        ("static-reports", layout.path("static-reports")),
    )
    arguments: list[str] = []
    for name, path in pairs:
        arguments.extend(("--workspace", f"{name}={path}"))
    return arguments


def _write_control(root: Path, layout: Layout) -> Path:
    matrix = load_json(root / "packaging/honey/artifact-matrix.v1.json")
    control = {
        "schema_version": honey_evidence.INPUT_SCHEMA_VERSION,
        "source": {"workspace": "source", "path": "source-descriptor.json"},
        "artifacts": _artifact_rows(layout, matrix),
        "evidence": _evidence_rows(
            root,
            layout,
            layout.path("gate-reports"),
            layout.path("static-reports"),
        ),
    }
    destination = layout.path("evidence-control")
    with EvidenceWorkspace.create(destination, repository_root=root) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        workspace.write_json(honey_evidence.INPUT_NAME, control)
        workspace.read_files({honey_evidence.INPUT_NAME}, strict_read_only=True)
    return destination


def _run_demos(
    root: Path, layout: Layout, environment: dict[str, str], python: str
) -> None:
    installed_demos = layout.path("installed-demos")
    common = [
        python,
        os.fspath(installed_demos / "demos/run_honey.py"),
        "--manifest",
        os.fspath(installed_demos / "demos/honey-manifest.v1.json"),
        "--runtime-archive",
        os.fspath(layout.candidate / RUNTIME_NAME),
        "--runtime-sha256",
        sha256_file(layout.candidate / RUNTIME_NAME),
        "--python-wheel",
        os.fspath(layout.candidate / PYTHON_WHEEL_NAME),
        "--python-wheel-sha256",
        sha256_file(layout.candidate / PYTHON_WHEEL_NAME),
        "--claude-plugin-archive",
        os.fspath(layout.candidate / CLAUDE_NAME),
        "--claude-plugin-sha256",
        sha256_file(layout.candidate / CLAUDE_NAME),
    ]
    _run(
        root,
        [
            *common,
            "--scenario",
            "two-agent",
            "--evidence-dir",
            os.fspath(layout.path("demo-two-agent")),
            "--output",
            "two-agent-demo-report.json",
        ],
        environment=environment,
        label="installed two-agent demo twice",
    )
    _run(
        root,
        [
            *common,
            "--scenario",
            "offline-context",
            "--scenario",
            "effect-recovery-replay",
            "--scenario",
            "claude-mcp",
            "--evidence-dir",
            os.fspath(layout.path("demo-other")),
            "--output",
            "other-demo-report.json",
        ],
        environment=environment,
        label="other installed Honey demos twice",
    )


def _docs_variables(root: Path, layout: Layout) -> dict[str, str]:
    variables_root = layout.path("docs-variables")
    variables_root.mkdir(mode=0o700)
    empty = variables_root / "empty"
    unicode_workspace = variables_root / "workspace with spaces δοκιμή"
    for path in (empty, unicode_workspace):
        path.mkdir(mode=0o700)
    return {
        "BINARY_ARCHIVE": os.fspath(layout.candidate / RUNTIME_NAME),
        "CIGAR_BIN": os.fspath(layout.path("docs-installed-runtime") / "bin/cigar"),
        "CIGAR_QUALIFICATION_TOOL_ARCHIVE": os.fspath(layout.tools / TOOL_NAME),
        "CIGAR_QUALIFICATION_TOOL_BUILD_RECEIPT": os.fspath(
            layout.tools / "macos-conformance-development-build.json"
        ),
        "CIGAR_RUNTIME_BUILD_RECEIPT": os.fspath(
            layout.native / "native-build-receipt.json"
        ),
        "CIGAR_SOURCE_ROOT": os.fspath(root),
        "DIST_DIRECTORY": os.fspath(layout.candidate),
        "EMPTY_WORKSPACE": os.fspath(empty),
        "HONEY_CLAUDE_PLUGIN_ARCHIVE": os.fspath(layout.candidate / CLAUDE_NAME),
        "HONEY_CLAUDE_PLUGIN_SHA256": sha256_file(layout.candidate / CLAUDE_NAME),
        "HONEY_DEMOS_ARCHIVE": os.fspath(layout.candidate / DEMO_NAME),
        "HONEY_DEMOS_SHA256": sha256_file(layout.candidate / DEMO_NAME),
        "HONEY_DOCS_EVIDENCE_DIR": os.fspath(layout.path("docs-command-reports")),
        "HONEY_PYTHON_WHEEL": os.fspath(layout.candidate / PYTHON_WHEEL_NAME),
        "HONEY_PYTHON_WHEEL_SHA256": sha256_file(layout.candidate / PYTHON_WHEEL_NAME),
        "HONEY_RUNTIME_ARCHIVE": os.fspath(layout.candidate / RUNTIME_NAME),
        "HONEY_RUNTIME_SHA256": sha256_file(layout.candidate / RUNTIME_NAME),
        "UNICODE_WORKSPACE": os.fspath(unicode_workspace),
    }


def _extract_candidate_archive(archive_path: Path, target: Path) -> None:
    target.mkdir(mode=0o700)
    entries = 0
    total = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            entries += 1
            if entries > 10_000:
                raise HoneyQualificationError("candidate archive has too many members")
            relative = safe_relative_path(member.name.rstrip("/"))
            destination = target.joinpath(*relative.split("/"))
            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise HoneyQualificationError(
                    "candidate archive contains a link or special member"
                )
            total += member.size
            if member.size < 0 or member.size > 512 * 1024 * 1024 or total > 2**31:
                raise HoneyQualificationError(
                    "candidate archive exceeds installed extraction bounds"
                )
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise HoneyQualificationError("candidate archive member is unreadable")
            with source, destination.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if destination.stat().st_size != member.size:
                raise HoneyQualificationError("candidate archive member changed length")
            destination.chmod(member.mode & 0o777)


def _extract_candidate_archives(layout: Layout) -> None:
    _extract_candidate_archive(
        layout.candidate / RUNTIME_NAME,
        layout.path("docs-installed-runtime"),
    )
    _extract_candidate_archive(
        layout.candidate / DEMO_NAME,
        layout.path("installed-demos"),
    )


def _qualify(root: Path, layout: Layout, epoch: int) -> dict[str, Any]:
    before = _source_identity(root)
    environment = _environment(epoch)
    environment["CIGAR_NO_EGRESS_ENFORCED"] = "1"
    python = sys.executable
    public = verify_public_candidate(layout.candidate, root)
    if public.get("status") != "passed-artifact-integrity":
        raise HoneyQualificationError("public candidate integrity is not established")
    _run(
        root,
        [
            python,
            "scripts/release/qualify_install.py",
            os.fspath(layout.candidate / RUNTIME_NAME),
            "--contract",
            "packaging/contracts/macos-runtime-archive.v1.json",
            "--runtime-build-receipt",
            os.fspath(layout.native / "native-build-receipt.json"),
            "--qualification-tool-archive",
            os.fspath(layout.tools / TOOL_NAME),
            "--qualification-tool-contract",
            "packaging/contracts/macos-conformance-runner.v1.json",
            "--qualification-tool-build-receipt",
            os.fspath(layout.tools / "macos-conformance-development-build.json"),
            "--expected-artifact-id",
            "macos-runtime-aarch64",
            "--expected-target",
            TARGET,
            "--expected-version",
            VERSION,
            "--expected-abi",
            ABI,
            "--evidence-dir",
            os.fspath(layout.path("installed")),
            "--report",
            "installed-runtime-report.json",
        ],
        environment=environment,
        label="standard-user installed runtime",
    )
    _run(
        root,
        [
            python,
            "scripts/release/qualify_claude_code_plugin.py",
            "--runtime-archive",
            os.fspath(layout.candidate / RUNTIME_NAME),
            "--runtime-archive-sha256",
            sha256_file(layout.candidate / RUNTIME_NAME),
            "--plugin-archive",
            os.fspath(layout.candidate / CLAUDE_NAME),
            "--plugin-archive-sha256",
            sha256_file(layout.candidate / CLAUDE_NAME),
            "--fixed-host",
            "--source-date-epoch",
            str(epoch),
            "--evidence-dir",
            os.fspath(layout.path("claude-qualification")),
        ],
        environment=environment,
        label="Claude Code installed lifecycle",
    )
    _extract_candidate_archives(layout)
    _run_demos(root, layout, environment, python)
    variables = _docs_variables(root, layout)
    variables_workspace = layout.path("docs-variables-file")
    with EvidenceWorkspace.create(
        variables_workspace, repository_root=root
    ) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        workspace.write_json("variables.json", variables)
        workspace.read_files({"variables.json"}, strict_read_only=True)
    _run(
        root,
        [
            python,
            "scripts/release/check_docs.py",
            "--execute",
            "installed-candidate",
            "--variables",
            os.fspath(variables_workspace / "variables.json"),
            "--evidence-dir",
            os.fspath(layout.path("docs-report")),
            "--report",
            "documentation-report.json",
        ],
        environment=environment,
        label="installed documentation commands and links",
    )
    _run(
        root,
        [
            python,
            "scripts/release/build_honey_gate_reports.py",
            "--candidate",
            os.fspath(layout.candidate),
            "--source-descriptor",
            os.fspath(layout.source / "source-descriptor.json"),
            "--typescript-receipt",
            os.fspath(layout.typescript / "typescript-sdk-build-receipt.json"),
            "--python-receipt",
            os.fspath(layout.python / "python-sdk-build-receipt.json"),
            "--rust-receipt",
            os.fspath(layout.rust / "rust-sdk-local-registry-build-receipt.json"),
            "--evidence-dir",
            os.fspath(layout.path("gate-reports")),
        ],
        environment=environment,
        label="bounded safety, secret, and dependency reports",
        timeout=7_200,
    )
    static_reports = _copy_static_reports(root, layout)
    control = _write_control(root, layout)
    evidence_command = [
        python,
        "scripts/release/build_honey_evidence.py",
        "build",
        "--control-workspace",
        os.fspath(control),
        *_workspace_arguments(layout),
        "--evidence-dir",
        os.fspath(layout.path("evidence-ledger")),
    ]
    _run(
        root,
        evidence_command,
        environment=environment,
        label="Honey private evidence ledger",
    )
    check = _check_evidence(root, layout, environment, python)
    ledger = load_json(layout.path("evidence-ledger") / honey_evidence.LEDGER_NAME)
    result = {
        "schema_version": "cigar.honey.qualification-result.v1",
        "status": "passed-developer-preview",
        "product_version": VERSION,
        "context_abi": ABI,
        "source_revision": before[0],
        "source_tree": before[1],
        "candidate_manifest_sha256": sha256_file(
            layout.candidate / "honey-release-manifest.json"
        ),
        "evidence_ledger_sha256": sha256_file(
            layout.path("evidence-ledger") / honey_evidence.LEDGER_NAME
        ),
        "evidence_root": ledger["aggregate"]["sha256"],
        "public_verification_status": public["status"],
        "private_evidence_status": check["status"],
        "claims": {
            "prerelease": True,
            "published": False,
            "supported": False,
            "production_qualified": False,
        },
    }
    qualification = layout.path("qualification")
    with EvidenceWorkspace.create(qualification, repository_root=root) as workspace:
        workspace.read_files(set(), strict_read_only=False)
        workspace.write_json(QUALIFICATION_RESULT, result)
        workspace.read_files({QUALIFICATION_RESULT}, strict_read_only=True)
    if (
        static_reports != layout.path("static-reports")
        or _source_identity(root) != before
    ):
        raise HoneyQualificationError("source changed during Honey qualification")
    return result


def _check_evidence(
    root: Path, layout: Layout, environment: dict[str, str], python: str
) -> dict[str, Any]:
    command = [
        python,
        "scripts/release/build_honey_evidence.py",
        "check",
        "--control-workspace",
        os.fspath(layout.path("evidence-control")),
        *_workspace_arguments(layout),
        "--ledger-workspace",
        os.fspath(layout.path("evidence-ledger")),
    ]
    payload = _run(
        root,
        command,
        environment=environment,
        label="non-mutating evidence reconstruction",
    )
    document = load_json_bytes(payload, "Honey evidence check")
    if document.get("status") != "passed-developer-preview":
        raise HoneyQualificationError("Honey evidence check did not pass")
    return document


def _verify(root: Path, layout: Layout, epoch: int) -> dict[str, Any]:
    before = _source_identity(root)
    public = verify_public_candidate(layout.candidate, root)
    check = _check_evidence(root, layout, _environment(epoch), sys.executable)
    qualification_path = layout.path("qualification") / QUALIFICATION_RESULT
    qualification = load_json(qualification_path)
    ledger_path = layout.path("evidence-ledger") / honey_evidence.LEDGER_NAME
    ledger = load_json(ledger_path)
    expected = {
        "schema_version": "cigar.honey.qualification-result.v1",
        "status": "passed-developer-preview",
        "product_version": VERSION,
        "context_abi": ABI,
        "source_revision": before[0],
        "source_tree": before[1],
        "candidate_manifest_sha256": sha256_file(
            layout.candidate / "honey-release-manifest.json"
        ),
        "evidence_ledger_sha256": sha256_file(ledger_path),
        "evidence_root": ledger["aggregate"]["sha256"],
        "public_verification_status": "passed-artifact-integrity",
        "private_evidence_status": "passed-developer-preview",
        "claims": {
            "prerelease": True,
            "published": False,
            "supported": False,
            "production_qualified": False,
        },
    }
    if public.get("status") != "passed-artifact-integrity" or qualification != expected:
        raise HoneyQualificationError("combined Honey qualification result is stale")
    if check.get("evidence_root") != qualification["evidence_root"]:
        raise HoneyQualificationError("evidence reconstruction root changed")
    if _source_identity(root) != before:
        raise HoneyQualificationError("source changed during non-mutating verification")
    return qualification


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve(strict=True)
    epoch = _epoch(root, arguments.source_date_epoch)
    create = arguments.command in {"build", "all"}
    evidence_root = _external_root(arguments.evidence_root, root, create=create)
    layout = Layout(evidence_root)
    if arguments.command == "build":
        result = _build(root, layout, epoch)
    elif arguments.command == "qualify":
        result = _qualify(root, layout, epoch)
    elif arguments.command == "verify":
        result = _verify(root, layout, epoch)
    else:
        _build(root, layout, epoch)
        result = _qualify(root, layout, epoch)
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        OSError,
        ReleaseError,
        SourceDescriptorError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"Honey qualification failed: {error}") from error
