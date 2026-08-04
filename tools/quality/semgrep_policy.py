#!/usr/bin/env python3
"""Hydrate, verify, and run CIGAR's digest-pinned Semgrep policy.

Hydration is the only network-capable operation. Scanning consumes the already
verified effective ruleset with Semgrep metrics disabled and writes its raw
report plus a content-free receipt outside the source checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path(__file__).with_name("semgrep-policy.v1.json")
MAX_RULESET_BYTES = 8 * 1024 * 1024
RULESET_CANONICALIZATION = "cigar.semgrep-rule-block-order.v1"
RULESET_HEADER = b"rules:\n"
RULE_ID_PATTERN = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")


class PolicyError(RuntimeError):
    """The scanner policy, ruleset, source, or result failed closed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot read Semgrep policy: {error}") from error
    if policy.get("schema_version") != "cigar.semgrep-policy.v1":
        raise PolicyError("unsupported Semgrep policy schema")
    scanner = policy.get("scanner")
    upstream = policy.get("upstream_ruleset")
    effective = policy.get("effective_ruleset")
    scan = policy.get("scan")
    exceptions = policy.get("rule_exceptions")
    if not isinstance(scanner, dict) or scanner.get("name") != "semgrep":
        raise PolicyError("Semgrep scanner identity is missing")
    if not isinstance(scanner.get("version"), str) or not scanner["version"]:
        raise PolicyError("Semgrep scanner version is missing")
    if not isinstance(upstream, dict):
        raise PolicyError("upstream ruleset descriptor is missing")
    canonical_upstream = upstream.get("canonical")
    for name, descriptor in (
        ("canonical upstream", canonical_upstream),
        ("effective", effective),
    ):
        if not isinstance(descriptor, dict):
            raise PolicyError(f"{name} ruleset descriptor is missing")
        digest = descriptor.get("sha256")
        size = descriptor.get("bytes")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(size, int)
            or size <= 0
            or size > MAX_RULESET_BYTES
        ):
            raise PolicyError(f"{name} ruleset descriptor is invalid")
    if upstream.get("canonicalization") != RULESET_CANONICALIZATION:
        raise PolicyError("upstream ruleset canonicalization is unsupported")
    if (
        not isinstance(upstream.get("rule_count"), int)
        or not 1 <= upstream["rule_count"] <= 100_000
    ):
        raise PolicyError("upstream ruleset count is invalid")
    if not isinstance(upstream.get("url"), str):
        raise PolicyError("upstream ruleset URL is missing")
    parsed_url = urllib.parse.urlparse(upstream["url"])
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "semgrep.dev"
        or parsed_url.path != "/c/p/default"
        or parsed_url.params
        or parsed_url.query
        or parsed_url.fragment
        or parsed_url.username
        or parsed_url.password
        or parsed_url.port is not None
    ):
        raise PolicyError("upstream ruleset URL is outside the pinned authority")
    if not isinstance(scan, dict):
        raise PolicyError("scan configuration is missing")
    if not isinstance(scan.get("exclude"), list) or not all(
        isinstance(item, str) and item and item not in {"*", "**", "."}
        for item in scan["exclude"]
    ):
        raise PolicyError("scan exclusions are invalid")
    if scan.get("use_git_ignore") is not False:
        raise PolicyError("the policy must scan untracked source files")
    if (
        not isinstance(scan.get("timeout_seconds"), int)
        or not 1 <= scan["timeout_seconds"] <= 300
    ):
        raise PolicyError("scan timeout is invalid")
    if not isinstance(exceptions, list) or len(exceptions) != 1:
        raise PolicyError("the exact Semgrep exception authority is invalid")
    return policy


def verify_descriptor(payload: bytes, descriptor: dict[str, Any], label: str) -> None:
    if len(payload) != descriptor["bytes"]:
        raise PolicyError(
            f"{label} ruleset size mismatch: expected {descriptor['bytes']}, got {len(payload)}"
        )
    actual = sha256_bytes(payload)
    if actual != descriptor["sha256"]:
        raise PolicyError(
            f"{label} ruleset digest mismatch: expected {descriptor['sha256']}, got {actual}"
        )


def canonicalize_upstream_ruleset(payload: bytes, descriptor: dict[str, Any]) -> bytes:
    """Remove registry rule-order variance without normalizing rule content."""

    if descriptor.get("canonicalization") != RULESET_CANONICALIZATION:
        raise PolicyError("upstream ruleset canonicalization is unsupported")
    expected_count = descriptor.get("rule_count")
    if not isinstance(expected_count, int) or not 1 <= expected_count <= 100_000:
        raise PolicyError("upstream ruleset count is invalid")
    if (
        not payload.startswith(RULESET_HEADER + b"- ")
        or not payload.endswith(b"\n")
        or b"\r" in payload
        or b"\x00" in payload
    ):
        raise PolicyError("upstream Semgrep ruleset framing is invalid")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("upstream Semgrep ruleset is not UTF-8") from error

    body = payload[len(RULESET_HEADER) :]
    starts = [0]
    offset = body.find(b"\n- ")
    while offset >= 0:
        starts.append(offset + 1)
        offset = body.find(b"\n- ", offset + 3)
    blocks = [
        body[start:end]
        for start, end in zip(starts, starts[1:] + [len(body)], strict=True)
    ]
    if len(blocks) != expected_count:
        raise PolicyError(
            "upstream Semgrep rule count mismatch: "
            f"expected {expected_count}, got {len(blocks)}"
        )

    identified: list[tuple[bytes, bytes]] = []
    for block in blocks:
        if not block.startswith(b"- ") or not block.endswith(b"\n"):
            raise PolicyError("upstream Semgrep rule block framing is invalid")
        candidates = []
        for line in block.splitlines():
            if line.startswith((b"- id: ", b"  id: ")):
                candidate = line[6:]
                if RULE_ID_PATTERN.fullmatch(candidate) is None:
                    raise PolicyError("upstream Semgrep rule ID is invalid")
                candidates.append(candidate)
        if len(candidates) != 1:
            raise PolicyError("upstream Semgrep rule block must contain one rule ID")
        identified.append((candidates[0], block))

    identifiers = [identifier for identifier, _ in identified]
    if len(identifiers) != len(set(identifiers)):
        raise PolicyError("upstream Semgrep rule IDs must be unique")
    return RULESET_HEADER + b"".join(
        block for _, block in sorted(identified, key=lambda item: item[0])
    )


def verify_exception_subject(exception: dict[str, Any], root: Path = ROOT) -> None:
    relative = exception.get("path")
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith(("/", "\\"))
    ):
        raise PolicyError("Semgrep exception path is invalid")
    subject = (root / relative).resolve(strict=True)
    try:
        subject.relative_to(root.resolve(strict=True))
    except ValueError as error:
        raise PolicyError("Semgrep exception escapes the repository") from error
    payload = subject.read_bytes()
    if len(payload) != exception.get("subject_bytes"):
        raise PolicyError("Semgrep exception subject size changed")
    if sha256_bytes(payload) != exception.get("subject_sha256"):
        raise PolicyError("Semgrep exception subject digest changed")
    if (
        not isinstance(exception.get("rationale"), str)
        or len(exception["rationale"]) < 80
    ):
        raise PolicyError("Semgrep exception rationale is missing")


def apply_exact_exceptions(
    upstream_payload: bytes,
    policy: dict[str, Any],
    *,
    root: Path = ROOT,
) -> bytes:
    try:
        rendered = upstream_payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("upstream Semgrep ruleset is not UTF-8") from error
    for exception in policy["rule_exceptions"]:
        verify_exception_subject(exception, root)
        rule_id = exception.get("rule_id")
        relative = exception.get("path")
        if not isinstance(rule_id, str) or not rule_id or not isinstance(relative, str):
            raise PolicyError("Semgrep exception identity is invalid")
        rule_marker = f"- id: {rule_id}\n"
        if rendered.count(rule_marker) != 1:
            raise PolicyError(f"expected exactly one pinned rule named {rule_id}")
        rule_start = rendered.index(rule_marker)
        next_rule = rendered.find("\n- ", rule_start + len(rule_marker))
        if next_rule < 0:
            next_rule = len(rendered)
        rule_block = rendered[rule_start:next_rule]
        insertion_marker = "  patterns:\n"
        if rule_block.count(insertion_marker) != 1 or "\n  paths:\n" in rule_block:
            raise PolicyError(
                f"pinned rule {rule_id} cannot accept the exact path exception"
            )
        insertion = f"  paths:\n    exclude:\n    - /{relative}\n"
        rule_block = rule_block.replace(
            insertion_marker, insertion + insertion_marker, 1
        )
        rendered = rendered[:rule_start] + rule_block + rendered[next_rule:]
    effective = rendered.encode("utf-8")
    verify_descriptor(effective, policy["effective_ruleset"], "effective")
    return effective


def prepare_external_output(path: Path, repository: Path, label: str) -> Path:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise PolicyError(f"{label} must be a normalized absolute path")
    parent = path.parent
    if not parent.exists():
        try:
            parent.mkdir(mode=0o700)
        except OSError as error:
            raise PolicyError(
                f"cannot create private {label} parent: {error}"
            ) from error
    try:
        resolved_parent = parent.resolve(strict=True)
        metadata = parent.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect {label} parent: {error}") from error
    if (
        resolved_parent != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PolicyError(f"{label} parent must be a canonical owner-only directory")
    resolved = resolved_parent / path.name
    require_external(resolved, repository, label)
    if resolved.exists() or resolved.is_symlink():
        raise PolicyError(f"{label} must be create-new")
    return resolved


def atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except OSError as error:
            raise PolicyError(
                f"cannot create protected output {path.name}: {error}"
            ) from error
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        parent_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def hydrate(output: Path, policy: dict[str, Any]) -> None:
    output = prepare_external_output(output, ROOT, "Semgrep ruleset")
    upstream = policy["upstream_ruleset"]
    request = urllib.request.Request(
        upstream["url"],
        headers={"User-Agent": "cigar-semgrep-policy/1"},
        method="GET",
    )
    try:
        # `load_policy` has already reduced this to one credential-free HTTPS host/path authority.
        # fmt: off
        with urllib.request.urlopen(request, timeout=60) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            # fmt: on
            if response.geturl() != upstream["url"]:
                raise PolicyError("Semgrep ruleset download was redirected")
            payload = response.read(MAX_RULESET_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise PolicyError(f"cannot hydrate pinned Semgrep ruleset: {error}") from error
    if len(payload) > MAX_RULESET_BYTES:
        raise PolicyError("Semgrep ruleset exceeds the hydration bound")
    canonical = canonicalize_upstream_ruleset(payload, upstream)
    verify_descriptor(canonical, upstream["canonical"], "canonical upstream")
    effective = apply_exact_exceptions(canonical, policy)
    atomic_write(output, effective)


def verify_effective_ruleset(path: Path, policy: dict[str, Any]) -> None:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise PolicyError(f"cannot read effective Semgrep ruleset: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise PolicyError(
            "effective Semgrep ruleset must be an owner-only regular file"
        )
    verify_descriptor(payload, policy["effective_ruleset"], "effective")
    for exception in policy["rule_exceptions"]:
        verify_exception_subject(exception)


def require_external(path: Path, repository: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(repository.resolve(strict=True))
    except ValueError:
        return resolved
    raise PolicyError(f"{label} must be outside the source checkout")


def git_value(repository: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
    )
    value = process.stdout.strip()
    if process.returncode != 0 or not value:
        raise PolicyError(f"git {' '.join(arguments)} failed")
    return value


def scanner_version(executable: str) -> str:
    process = subprocess.run(
        [executable, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
    )
    if process.returncode != 0:
        raise PolicyError("cannot determine Semgrep version")
    return process.stdout.strip().splitlines()[0]


def scan(
    repository: Path,
    ruleset: Path,
    report: Path,
    receipt: Path,
    executable: str,
    policy: dict[str, Any],
) -> bool:
    repository = repository.resolve(strict=True)
    report = prepare_external_output(report, repository, "Semgrep report")
    receipt = prepare_external_output(receipt, repository, "Semgrep receipt")
    if report == receipt:
        raise PolicyError("Semgrep report and receipt paths must differ")
    verify_effective_ruleset(ruleset, policy)
    actual_version = scanner_version(executable)
    expected_version = policy["scanner"]["version"]
    if actual_version != expected_version:
        raise PolicyError(
            f"Semgrep version mismatch: expected {expected_version}, got {actual_version}"
        )
    command = [
        executable,
        "scan",
        "--config",
        str(ruleset.resolve(strict=True)),
        "--error",
        "--timeout",
        str(policy["scan"]["timeout_seconds"]),
        "--metrics",
        "off",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
    ]
    for excluded in policy["scan"]["exclude"]:
        command.extend(("--exclude", excluded))
    command.extend(("--json-output", str(report), "."))
    previous_umask = os.umask(0o077)
    try:
        process = subprocess.run(command, cwd=repository, check=False, timeout=1800)
    finally:
        os.umask(previous_umask)
    try:
        report_metadata = report.lstat()
        raw_report = report.read_bytes()
        parsed_report = json.loads(raw_report)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(
            f"Semgrep did not produce a valid JSON report: {error}"
        ) from error
    if (
        not stat.S_ISREG(report_metadata.st_mode)
        or stat.S_ISLNK(report_metadata.st_mode)
        or report_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(report_metadata.st_mode) != 0o600
    ):
        raise PolicyError("Semgrep report must be an owner-only regular file")
    results = parsed_report.get("results")
    errors = parsed_report.get("errors")
    if not isinstance(results, list) or not isinstance(errors, list):
        raise PolicyError("Semgrep report omits results or errors")
    dirty_output = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if dirty_output.returncode != 0:
        raise PolicyError("cannot determine source checkout state")
    passed = process.returncode == 0 and not results and not errors
    normalized_command = [
        "semgrep",
        "scan",
        "--config",
        "${PINNED_RULESET}",
        "--error",
        "--timeout",
        str(policy["scan"]["timeout_seconds"]),
        "--metrics",
        "off",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
    ]
    for excluded in policy["scan"]["exclude"]:
        normalized_command.extend(("--exclude", excluded))
    normalized_command.extend(("--json-output", "${REPORT}", "."))
    evidence = {
        "candidate": {
            "dirty": bool(dirty_output.stdout),
            "git_commit": git_value(repository, "rev-parse", "HEAD"),
            "git_tree": git_value(repository, "rev-parse", "HEAD^{tree}"),
            "status_sha256": sha256_bytes(dirty_output.stdout),
        },
        "command_sha256": sha256_bytes(canonical_json_bytes(normalized_command)),
        "effective_ruleset": policy["effective_ruleset"],
        "error_count": len(errors),
        "finding_count": len(results),
        "release_eligible": passed and not dirty_output.stdout,
        "report": {"bytes": len(raw_report), "sha256": sha256_bytes(raw_report)},
        "scanner": {"name": "semgrep", "version": actual_version},
        "schema_version": "cigar.semgrep-evidence.v1",
        "status": "passed" if passed else "failed",
        "upstream_ruleset": {
            "canonical": policy["upstream_ruleset"]["canonical"],
            "canonicalization": policy["upstream_ruleset"]["canonicalization"],
            "rule_count": policy["upstream_ruleset"]["rule_count"],
            "url": policy["upstream_ruleset"]["url"],
        },
    }
    atomic_write(receipt, canonical_json_bytes(evidence))
    return passed


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    hydrate_parser = subparsers.add_parser(
        "hydrate", help="download and pin the ruleset"
    )
    hydrate_parser.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify", help="verify an effective ruleset")
    verify_parser.add_argument("--ruleset", required=True, type=Path)
    scan_parser = subparsers.add_parser("scan", help="run the pinned offline scan")
    scan_parser.add_argument("--repository", default=ROOT, type=Path)
    scan_parser.add_argument("--ruleset", required=True, type=Path)
    scan_parser.add_argument("--report", required=True, type=Path)
    scan_parser.add_argument("--receipt", required=True, type=Path)
    scan_parser.add_argument("--semgrep", default="semgrep")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        policy = load_policy()
        if arguments.command == "hydrate":
            hydrate(arguments.output, policy)
        elif arguments.command == "verify":
            verify_effective_ruleset(arguments.ruleset, policy)
        elif arguments.command == "scan":
            if not scan(
                arguments.repository,
                arguments.ruleset,
                arguments.report,
                arguments.receipt,
                arguments.semgrep,
                policy,
            ):
                return 1
        else:  # pragma: no cover - argparse enforces the command set.
            raise PolicyError("unsupported command")
    except (PolicyError, subprocess.TimeoutExpired) as error:
        print(f"semgrep policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
