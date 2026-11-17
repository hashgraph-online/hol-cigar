#!/usr/bin/env python3
"""Collect unapproved CI tool proposals, then consume independent approvals.

Collection never exports an xtask selector. Execution requires a separately
maintained repository variable; neither observed hashes nor a diagnostic receipt
are accepted as approval. The underlying xtask authority and receipt contracts
remain authoritative, including their explicit non-release-eligible status.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates" / "xtask"))
import tool_authority as authority  # noqa: E402
from command_plane_evidence import verify_record  # noqa: E402


APPROVAL_SCHEMA = "cigar.ci-xtask-approval.v1"
PROPOSAL_SCHEMA = "cigar.ci-xtask-review-proposal.v1"
LANES = {
    "source-quality": (
        "format-check",
        "generate-check",
        "test-vectors",
        "lint",
        "docs-check",
    ),
    "dependency-policy": ("lint",),
    "coverage": ("test-coverage-verify",),
}
COMMANDS = {
    "format-check": ("fmt", "--check"),
    "generate-check": ("generate", "--check"),
    "test-vectors": ("test", "vectors"),
    "lint": ("lint",),
    "docs-check": ("docs", "--check"),
    "test-coverage-verify": ("test", "coverage", "--verify"),
}
SELECTORS = ("CIGAR_XTASK_TOOL_INPUTS", "CIGAR_XTASK_TOOL_INPUTS_SHA256")
RUST_LAUNCHERS = (
    "cargo",
    "cargo-clippy",
    "cargo-fmt",
    "clippy-driver",
    "rustc",
    "rustdoc",
    "rustfmt",
    "rustup",
)


def write_new(path: Path, document: Any) -> None:
    write_bytes_new(path, authority.canonical_json_bytes(document), 0o400)


def write_bytes_new(path: Path, payload: bytes, mode: int) -> None:
    private(path.parent)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def private(path: Path) -> Path:
    return Path(authority._private_directory(str(path), "CI authority workspace"))


def append_actions(path: Path, lines: list[str]) -> None:
    """Write only our fixed, single-line names/paths to an Actions command file."""
    if not path.is_absolute() or any("\n" in line or "\r" in line for line in lines):
        raise authority.ToolAuthorityError("unsafe Actions output")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "wb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise authority.ToolAuthorityError("unsafe Actions command file")
        stream.write(("\n".join(lines) + "\n").encode())


def prepare(arguments: argparse.Namespace) -> dict[str, Any]:
    root = arguments.root
    if not root.is_absolute() or root.parent.resolve(strict=True) != root.parent:
        raise authority.ToolAuthorityError("CI root parent must be canonical")
    authority._protected_lineage(root, "CI root")
    if ROOT == root or ROOT in root.parents:
        raise authority.ToolAuthorityError("CI root must be outside the checkout")
    root.mkdir(mode=0o700)
    private(root)
    environment = {}
    for name in sorted(authority.ENVIRONMENT):
        directory = root / name.lower()
        directory.mkdir(mode=0o700)
        environment[name] = str(private(directory))
    for directory in (
        root / "review",
        root / "go-bin",
        root / "launchers",
        root / "cargo_home" / "bin",
    ):
        directory.mkdir(mode=0o700)
    state = {"lane": arguments.lane, "environment": environment}
    write_new(root / "environment.json", state)
    # HOME is a child-authority input, never an ambient shell-variable override.
    values = [
        f"{name}={value}" for name, value in environment.items() if name != "HOME"
    ]
    values += [f"CIGAR_CI_TOOL_ROOT={root}", f"GOBIN={root / 'go-bin'}"]
    append_actions(arguments.github_env, values)
    append_actions(
        arguments.github_path, [str(root / "cargo_home" / "bin"), str(root / "go-bin")]
    )
    return {"lane": arguments.lane, "prepared": True}


def environment(root: Path, lane: str) -> dict[str, str]:
    private(root)
    document, _payload = authority._protected_document(
        root / "environment.json", "CI environment"
    )
    if set(document) != {"lane", "environment"} or document["lane"] != lane:
        raise authority.ToolAuthorityError("CI environment belongs to another lane")
    values = document["environment"]
    if not isinstance(values, dict):
        raise authority.ToolAuthorityError("CI environment is malformed")
    result = authority._parse_environment(
        [f"{name}={value}" for name, value in values.items()]
    )
    expected = {name: str(root / name.lower()) for name in authority.ENVIRONMENT}
    if result != expected:
        raise authority.ToolAuthorityError("CI environment roots were substituted")
    return result


def runner() -> dict[str, str]:
    result = {
        "image_os": os.environ.get("ImageOS", ""),
        "image_version": os.environ.get("ImageVersion", ""),
        "system": platform.system(),
        "architecture": platform.machine(),
    }
    if (
        result["system"] != "Darwin"
        or result["architecture"] != "arm64"
        or any(
            re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", value) is None
            for value in result.values()
        )
    ):
        raise authority.ToolAuthorityError(
            "CI requires an identified native macOS arm64 image"
        )
    return result


def observed_payload(path: Path) -> bytes:
    """Read bounded, stable executable bytes without executing or approving them."""
    authority._protected_lineage(path, "observed CI executable")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= authority.MAX_TOOL_BYTES
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not before.st_mode & stat.S_IXUSR
        ):
            raise authority.ToolAuthorityError(
                "observed CI tool is not a bounded protected executable"
            )
        remaining, chunks = before.st_size, []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise authority.ToolAuthorityError(
                    "observed CI tool changed while read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise authority.ToolAuthorityError("observed CI tool grew while read")
        after = os.fstat(descriptor)
        named = path.lstat()
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            or getattr(after, field) != getattr(named, field)
            for field in fields
        ):
            raise authority.ToolAuthorityError(
                "observed CI tool was replaced while read"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def stage_launchers(arguments: argparse.Namespace) -> dict[str, Any]:
    environment(arguments.root, arguments.lane)
    found = shutil.which("rustup")
    if found is None:
        raise authority.ToolAuthorityError(
            "the pinned bootstrap Rustup launcher is unavailable"
        )
    payload = observed_payload(Path(found).resolve(strict=True))
    digest = hashlib.sha256(payload).hexdigest()
    directory = private(arguments.root / "launchers")
    for name in RUST_LAUNCHERS:
        target = directory / name
        write_bytes_new(target, payload, 0o500)
        authority._reviewed_tool({"path": str(target), "sha256": digest}, name)
    append_actions(arguments.github_path, [str(directory)])
    return {
        "staged_launchers": list(RUST_LAUNCHERS),
        "approval_status": "unapproved-observation",
    }


def observed_tool(name: str) -> dict[str, str]:
    if name == "protoc-gen-es":
        selected = ROOT / "node_modules/@bufbuild/protoc-gen-es/bin/protoc-gen-es"
    else:
        found = shutil.which(name)
        if found is None:
            raise authority.ToolAuthorityError(
                f"required CI tool is unavailable: {name}"
            )
        selected = Path(found)
    path = selected.resolve(strict=True)
    # This is observation, not authorization. Reuse the race/ownership/size checks.
    entry = {
        "path": str(path),
        "sha256": hashlib.sha256(observed_payload(path)).hexdigest(),
    }
    return authority._reviewed_tool(entry, name)


def collect(arguments: argparse.Namespace) -> dict[str, Any]:
    values = environment(arguments.root, arguments.lane)
    source = authority.source_binding(ROOT)
    authority._validate_source(source, source)
    image = runner()
    routes = {}
    review = private(arguments.root / "review")
    for command_id in LANES[arguments.lane]:
        tools = {
            name: observed_tool(name)
            for name in sorted(authority.ROUTE_TOOLS[command_id])
        }
        observed = {"schema_version": authority.REVIEW_SCHEMA, "tools": tools}
        tools_path = review / f"{command_id}.observed-tools.json"
        write_new(tools_path, observed)
        result = authority.draft(
            argparse.Namespace(
                command_id=command_id,
                reviewed_tools=tools_path,
                environment=[f"{name}={value}" for name, value in values.items()],
                output=review / f"{command_id}.observed-authority.json",
            )
        )
        routes[command_id] = {
            "reviewed_tools": observed,
            "authority_sha256": result["sha256"],
        }
    proposal = {
        "schema_version": PROPOSAL_SCHEMA,
        "approval_status": "unapproved-observation",
        "release_eligible": False,
        "independent_review_required": True,
        "approval_candidate": {
            "schema_version": APPROVAL_SCHEMA,
            "lane": arguments.lane,
            "source": source,
            "runner": image,
            "routes": routes,
        },
    }
    if authority.source_binding(ROOT) != source:
        raise authority.ToolAuthorityError("source changed during CI collection")
    write_new(review / "proposal.json", proposal)
    return {
        "lane": arguments.lane,
        "approval_status": proposal["approval_status"],
        "routes": sorted(routes),
    }


def approval(lane: str) -> dict[str, Any]:
    payload = os.environ.get("CIGAR_CI_TOOL_APPROVAL", "").encode()
    if not 0 < len(payload) <= authority.MAX_DOCUMENT_BYTES:
        raise authority.ToolAuthorityError(
            "independent CI approval is missing or oversized"
        )
    try:
        document = authority.load_json_bytes(payload, "independent CI approval")
    except authority.ReleaseError as error:
        raise authority.ToolAuthorityError(
            "independent CI approval is not strict JSON"
        ) from error
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "lane",
        "source",
        "runner",
        "routes",
    }:
        raise authority.ToolAuthorityError("independent CI approval shape is invalid")
    source = authority.source_binding(ROOT)
    authority._validate_source(source, source)
    if (
        document["schema_version"] != APPROVAL_SCHEMA
        or document["lane"] != lane
        or document["source"] != source
        or document["runner"] != runner()
    ):
        raise authority.ToolAuthorityError(
            "independent CI approval is stale or for another source, lane or image"
        )
    routes = document["routes"]
    if not isinstance(routes, dict) or set(routes) != set(LANES[lane]):
        raise authority.ToolAuthorityError(
            "independent CI approval route inventory is not exact"
        )
    for command_id, entry in routes.items():
        if (
            not isinstance(entry, dict)
            or set(entry) != {"reviewed_tools", "authority_sha256"}
            or not isinstance(entry["authority_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["authority_sha256"]) is None
        ):
            raise authority.ToolAuthorityError(
                "independent CI approval route is malformed"
            )
        reviewed = entry["reviewed_tools"]
        if (
            not isinstance(reviewed, dict)
            or set(reviewed) != {"schema_version", "tools"}
            or reviewed["schema_version"] != authority.REVIEW_SCHEMA
        ):
            raise authority.ToolAuthorityError(
                "independent CI tool manifest is malformed"
            )
        authority._validate_tools(reviewed["tools"], authority.ROUTE_TOOLS[command_id])
    return document


def approved_authority(arguments: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    if arguments.command_id not in LANES[arguments.lane]:
        raise authority.ToolAuthorityError("command is not in this CI lane")
    values = environment(arguments.root, arguments.lane)
    reviewed = approval(arguments.lane)
    entry = reviewed["routes"][arguments.command_id]
    target = arguments.root / f"{arguments.command_id}.approved-authority.json"
    if arguments.action == "run":
        tools_path = arguments.root / f"{arguments.command_id}.approved-tools.json"
        write_new(tools_path, entry["reviewed_tools"])
        authority.draft(
            argparse.Namespace(
                command_id=arguments.command_id,
                reviewed_tools=tools_path,
                environment=[f"{name}={value}" for name, value in values.items()],
                output=target,
            )
        )
    authority.validate(
        argparse.Namespace(authority=target, expected_sha256=entry["authority_sha256"])
    )
    return reviewed, target


def verify(arguments: argparse.Namespace) -> dict[str, Any]:
    reviewed, target = approved_authority(arguments)
    entry = reviewed["routes"][arguments.command_id]
    receipt_path = (
        arguments.evidence_dir
        / "command-plane"
        / f"{arguments.command_id}.receipt.json"
    )
    receipt, _payload = authority._protected_document(
        receipt_path, "CI command receipt"
    )
    binding = receipt.get("tool_authority")
    expected_tools = {
        name: tool["sha256"] for name, tool in entry["reviewed_tools"]["tools"].items()
    }
    if (
        not isinstance(binding, dict)
        or binding.get("command_id") != arguments.command_id
        or binding.get("review_status") != "operator-reviewed"
        or binding.get("manifest")
        != {"bytes": target.stat().st_size, "sha256": entry["authority_sha256"]}
        or binding.get("tools") != expected_tools
        or not binding.get("executions")
    ):
        raise authority.ToolAuthorityError(
            "CI receipt lacks the independently reviewed route binding"
        )
    result = verify_record(
        root=ROOT,
        evidence_directory=arguments.evidence_dir,
        command_id=arguments.command_id,
        expected_source=reviewed["source"],
        attachment_relative=None,
        tool_authority=binding,
    )
    write_new(
        arguments.root / "review" / f"{arguments.command_id}.verified-receipt.json",
        result,
    )
    return {
        "command_id": arguments.command_id,
        "review_status": "operator-reviewed",
        "receipt_verified": True,
        "release_eligible": False,
    }


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    reviewed, target = approved_authority(arguments)
    entry = reviewed["routes"][arguments.command_id]
    child_environment = dict(os.environ)
    child_environment.pop("CIGAR_CI_TOOL_APPROVAL", None)
    for selector in SELECTORS:
        child_environment.pop(selector, None)
    child_environment[SELECTORS[0]] = str(target)
    child_environment[SELECTORS[1]] = entry["authority_sha256"]
    child_environment.update(environment(arguments.root, arguments.lane))
    cargo = (
        entry["reviewed_tools"]["tools"]["cargo"]["path"]
        if "cargo" in entry["reviewed_tools"]["tools"]
        else None
    )
    # Generation delegates no Cargo operations; the outer build still needs the
    # checked, pinned Rust launcher. Its identity is reviewed in source-quality.
    if cargo is None:
        cargo = reviewed["routes"]["format-check"]["reviewed_tools"]["tools"]["cargo"][
            "path"
        ]
    subprocess.run(
        [
            "cargo",
            "xtask",
            "--evidence-dir",
            str(arguments.evidence_dir),
            *COMMANDS[arguments.command_id],
        ],
        executable=cargo,
        cwd=ROOT,
        env=child_environment,
        check=True,
    )
    # Rust produces command receipts with the fixed system Python, so reopen
    # using that same producer runtime rather than silently changing the binding.
    subprocess.run(
        [
            "/usr/bin/python3",
            "-B",
            "-I",
            str(Path(__file__).resolve()),
            "verify",
            "--lane",
            arguments.lane,
            "--root",
            str(arguments.root),
            "--command-id",
            arguments.command_id,
            "--evidence-dir",
            str(arguments.evidence_dir),
        ],
        cwd=ROOT,
        check=True,
    )
    return {
        "command_id": arguments.command_id,
        "receipt_verified": True,
        "release_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "stage-launchers", "collect", "run", "verify"):
        command = commands.add_parser(action)
        command.add_argument("--lane", required=True, choices=sorted(LANES))
        command.add_argument("--root", required=True, type=Path)
        if action == "prepare":
            command.add_argument("--github-env", required=True, type=Path)
        if action in {"prepare", "stage-launchers"}:
            command.add_argument("--github-path", required=True, type=Path)
        if action in {"run", "verify"}:
            command.add_argument(
                "--command-id", required=True, choices=sorted(COMMANDS)
            )
            command.add_argument("--evidence-dir", required=True, type=Path)
    arguments = parser.parse_args()
    result = {
        "prepare": prepare,
        "stage-launchers": stage_launchers,
        "collect": collect,
        "run": run,
        "verify": verify,
    }[arguments.action](arguments)
    print(authority.canonical_json_bytes(result).decode(), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
        print(
            "CI tool authority failed: missing, unsafe, stale or unapproved input; no diagnostic fallback",
            file=sys.stderr,
        )
        raise SystemExit(2)
