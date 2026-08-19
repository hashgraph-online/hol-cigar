#!/usr/bin/env python3
"""Execute one published Honey documentation flow from exact release artifacts.

The driver is intentionally a thin, fail-closed bridge between the documentation
command registry and the packaged Honey demo runner.  It never builds from the
checkout: the runner and fixtures come from the supplied demo archive, while the
runtime and any supporting artifact are staged by independently supplied SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Never, Sequence

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import ReleaseError, canonical_json_bytes, load_json_bytes
from verify_package import verify as verify_package


ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = "0.9.4"
CONTEXT_ABI = "cigar.context.v1"
DEMOS_ARTIFACT_ID = "honey-demos"
DEMOS_CONTRACT_REFERENCE = "packaging/honey/contracts/demos-archive.v1.json"
DEMOS_CONTRACT = ROOT / "packaging/honey/contracts/demos-archive.v1.json"
REPORT_SCHEMA = "cigar.honey-installed-docs-command.v1"
DEMO_REPORT_SCHEMA = "cigar.honey-installed-demo-report.v1"
DEMO_EVIDENCE_CLASS = "cigar.honey-installed-demo.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
MAX_ARCHIVE_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024

FLOW_SCENARIOS = {
    "quickstart": "offline-context",
    "handoff": "two-agent",
    "effect-replay": "effect-recovery-replay",
    "claude-plugin": "claude-mcp",
}
FLOW_SUPPORT = {
    "quickstart": frozenset(),
    "handoff": frozenset({"python-wheel"}),
    "effect-replay": frozenset(),
    "claude-plugin": frozenset({"claude-plugin"}),
}
FLOW_COMPONENT_COUNTS = {
    "quickstart": 2,
    "handoff": 1,
    "effect-replay": 2,
    "claude-plugin": 1,
}
DEMO_REPORT_KEYS = {
    "schema_version",
    "status",
    "product_version",
    "context_abi",
    "evidence_class",
    "suite",
    "selected_scenarios",
    "runtime",
    "source",
    "supporting_artifacts",
    "scenarios",
    "installed_artifact_qualified",
    "report_digest",
}
STORY_KEYS = {"scenario_id", "status", "semantic_identity", "components"}
COMPONENT_KEYS = {
    "demo_id",
    "fixed_seed",
    "manifest_digest",
    "fixture_digest",
    "driver_digest",
    "driver_support_digest",
    "semantic_identity",
    "repeated_semantic_identity",
    "no_egress_enforcement",
    "assertions",
    "status",
}


class HoneyDocsQualificationError(ReleaseError):
    """One exact installed-candidate documentation flow did not qualify."""


def fail(message: str) -> Never:
    raise HoneyDocsQualificationError(message)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flow", choices=sorted(FLOW_SCENARIOS))
    parser.add_argument("--demos-archive", type=Path, required=True)
    parser.add_argument("--demos-sha256", required=True)
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--python-wheel", type=Path)
    parser.add_argument("--python-wheel-sha256")
    parser.add_argument("--claude-plugin-archive", type=Path)
    parser.add_argument("--claude-plugin-sha256")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="absolute external owner-only create-new evidence directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="safe relative receipt path beneath --evidence-dir",
    )
    return parser.parse_args(argv)


def _require_digest(value: str | None, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} must be an independently supplied lowercase SHA-256")
    return value


def _validate_selection(arguments: argparse.Namespace) -> None:
    _require_digest(arguments.demos_sha256, "demo archive digest")
    _require_digest(arguments.runtime_sha256, "runtime archive digest")
    for label, path in (
        ("demo archive", arguments.demos_archive),
        ("runtime archive", arguments.runtime_archive),
    ):
        if not path.is_absolute() or os.path.normpath(os.fspath(path)) != os.fspath(
            path
        ):
            fail(f"{label} path must be absolute and lexically canonical")
    pairs = {
        "python-wheel": (arguments.python_wheel, arguments.python_wheel_sha256),
        "claude-plugin": (
            arguments.claude_plugin_archive,
            arguments.claude_plugin_sha256,
        ),
    }
    supplied: set[str] = set()
    for label, (path, digest) in pairs.items():
        if (path is None) != (digest is None):
            fail(f"{label} path and digest must be supplied together")
        if path is not None:
            if not path.is_absolute() or os.path.normpath(os.fspath(path)) != os.fspath(
                path
            ):
                fail(f"{label} path must be absolute and lexically canonical")
            _require_digest(digest, f"{label} digest")
            supplied.add(label)
    expected = set(FLOW_SUPPORT[arguments.flow])
    if supplied != expected:
        fail(
            f"{arguments.flow} requires the exact supporting artifact set: "
            f"{sorted(expected)}"
        )
    if not arguments.evidence_dir.is_absolute():
        fail("--evidence-dir must be absolute")
    if arguments.output.is_absolute():
        fail("--output must be relative to --evidence-dir")
    safe_evidence_path(os.fspath(arguments.output))


def _stage_artifact(
    source: Path,
    destination: Path,
    expected_sha256: str,
    label: str,
) -> dict[str, Any]:
    expected_sha256 = _require_digest(expected_sha256, f"{label} digest")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = -1
    destination_fd = -1
    try:
        source_fd = os.open(source, flags)
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_ARTIFACT_BYTES
        ):
            fail(f"{label} must be a bounded, non-linked regular file")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(
                source_fd, min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - copied)
            )
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_ARTIFACT_BYTES:
                fail(f"{label} exceeds the artifact size bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    fail(f"{label} could not be staged")
                view = view[written:]
        after = os.fstat(source_fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            fail(f"{label} changed while it was staged")
        observed = digest.hexdigest()
        if copied != before.st_size or observed != expected_sha256:
            fail(f"{label} bytes do not match the independently supplied SHA-256")
        os.fsync(destination_fd)
    except HoneyDocsQualificationError:
        raise
    except OSError as error:
        raise HoneyDocsQualificationError(f"cannot securely stage {label}") from error
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    return {"sha256": expected_sha256, "bytes": copied}


def _safe_member_path(name: str) -> Path:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        fail("demo archive contains an unsafe member path")
    return Path(*pure.parts)


def _extract_demos(archive: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    seen: set[Path] = set()
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                fail("demo archive member count is outside the qualification bound")
            for member in members:
                relative = _safe_member_path(member.name.rstrip("/"))
                if relative in seen:
                    fail("demo archive contains duplicate normalized paths")
                seen.add(relative)
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False, mode=0o700)
                    continue
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.size < 0
                ):
                    fail("demo archive contains a link or special file")
                total += member.size
                if total > MAX_ARCHIVE_EXPANDED_BYTES:
                    fail("demo archive expanded bytes exceed the qualification bound")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                stream = source.extractfile(member)
                if stream is None:
                    fail("demo archive regular member has no payload")
                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
                target.chmod(0o600)
    except HoneyDocsQualificationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise HoneyDocsQualificationError(
            "cannot extract the verified demo archive"
        ) from error


def _clean_environment(home: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "WINDIR", "TMPDIR"}
    }
    environment.update(
        {
            "HOME": str(home),
            "PYTHONDONTWRITEBYTECODE": "1",
            "CARGO_NET_OFFLINE": "true",
            "UV_OFFLINE": "1",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "NO_COLOR": "1",
        }
    )
    return environment


def _run_packaged_runner(command: list[str], cwd: Path, home: Path) -> None:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=_clean_environment(home),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=900,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HoneyDocsQualificationError(
                "packaged Honey documentation scenario did not complete"
            ) from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if (
            stdout.tell() > MAX_PROCESS_OUTPUT_BYTES
            or stderr.tell() > MAX_PROCESS_OUTPUT_BYTES
        ):
            fail("packaged Honey documentation scenario exceeded its output bound")
        if completed.returncode != 0:
            fail("packaged Honey documentation scenario returned a non-zero status")


def _load_strict_report(path: Path) -> dict[str, Any]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 16 * 1024 * 1024
    ):
        fail("packaged Honey documentation scenario did not create a bounded report")
    value = load_json_bytes(path.read_bytes(), "packaged Honey demo report")
    if not isinstance(value, dict):
        fail("packaged Honey demo report is not an object")
    return value


def _canonical_without_newline(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise HoneyDocsQualificationError(
            "packaged Honey demo report cannot be canonicalized"
        ) from error


def _source_binding(
    demos_source: dict[str, Any], runtime_source: Any
) -> dict[str, Any]:
    expected_keys = {"revision", "tree_sha256", "committed", "clean"}
    if (
        not isinstance(runtime_source, dict)
        or set(demos_source) != expected_keys
        or set(runtime_source) != expected_keys
        or demos_source.get("revision") != runtime_source.get("revision")
        or not isinstance(demos_source.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", demos_source["revision"])
        is None
        or any(
            not isinstance(candidate.get("tree_sha256"), str)
            or SHA256.fullmatch(candidate["tree_sha256"]) is None
            or candidate.get("committed") is not True
            or candidate.get("clean") is not True
            for candidate in (demos_source, runtime_source)
        )
    ):
        fail("demo and runtime artifacts do not share one clean committed revision")
    return {
        "revision": demos_source["revision"],
        "demos": demos_source,
        "runtime": runtime_source,
    }


def _validate_demo_report(
    report: dict[str, Any],
    *,
    flow: str,
    suite_sha256: str,
    source: dict[str, Any],
    runtime: dict[str, Any],
    support: dict[str, dict[str, Any]],
) -> None:
    scenario = FLOW_SCENARIOS[flow]
    unsigned = dict(report)
    report_digest = unsigned.pop("report_digest", None)
    if (
        set(report) != DEMO_REPORT_KEYS
        or report.get("schema_version") != DEMO_REPORT_SCHEMA
        or report.get("status") != "installed_demo_passed"
        or report.get("product_version") != PRODUCT_VERSION
        or report.get("context_abi") != CONTEXT_ABI
        or report.get("evidence_class") != DEMO_EVIDENCE_CLASS
        or report.get("suite")
        != {
            "manifest": "demos/honey-manifest.v1.json",
            "sha256": suite_sha256,
        }
        or report.get("selected_scenarios") != [scenario]
        or report.get("installed_artifact_qualified") is not True
        or not isinstance(report_digest, str)
        or MULTIHASH.fullmatch(report_digest) is None
        or report_digest
        != "1220" + hashlib.sha256(_canonical_without_newline(unsigned)).hexdigest()
    ):
        fail("packaged Honey demo report did not qualify the selected scenario")
    _source_binding(source, report.get("source"))
    runtime_report = report.get("runtime")
    if (
        not isinstance(runtime_report, dict)
        or runtime_report.get("sha256") != runtime["sha256"]
        or runtime_report.get("bytes") != runtime["bytes"]
    ):
        fail("packaged Honey demo report is not bound to the staged runtime")
    expected_support = {
        "python-wheel": "python_wheel",
        "claude-plugin": "claude_plugin",
    }
    observed_support = report.get("supporting_artifacts")
    if not isinstance(observed_support, dict) or set(observed_support) != {
        expected_support[label] for label in support
    }:
        fail("packaged Honey demo report has the wrong supporting artifact set")
    for label, identity in support.items():
        observed = observed_support[expected_support[label]]
        if (
            not isinstance(observed, dict)
            or observed.get("sha256") != identity["sha256"]
            or observed.get("bytes") != identity["bytes"]
        ):
            fail("packaged Honey demo report is not bound to a supporting artifact")
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 1:
        fail("packaged Honey demo report has an incomplete scenario inventory")
    story = scenarios[0]
    components = story.get("components") if isinstance(story, dict) else None
    if (
        not isinstance(story, dict)
        or set(story) != STORY_KEYS
        or story.get("scenario_id") != scenario
        or story.get("status") != "installed_story_passed_twice"
        or not isinstance(story.get("semantic_identity"), str)
        or MULTIHASH.fullmatch(story["semantic_identity"]) is None
        or not isinstance(components, list)
        or len(components) != FLOW_COMPONENT_COUNTS[flow]
    ):
        fail("packaged Honey demo story did not pass twice")
    for component in components:
        assertions = (
            component.get("assertions") if isinstance(component, dict) else None
        )
        if (
            not isinstance(component, dict)
            or set(component) != COMPONENT_KEYS
            or component.get("status") != "installed_component_passed_twice"
            or component.get("no_egress_enforcement") != "darwin-loopback-only-v1"
            or not isinstance(component.get("semantic_identity"), str)
            or MULTIHASH.fullmatch(component["semantic_identity"]) is None
            or component.get("semantic_identity")
            != component.get("repeated_semantic_identity")
            or not isinstance(assertions, list)
            or not assertions
            or any(
                not isinstance(assertion, dict)
                or set(assertion) != {"assertion_id", "status", "evidence_digest"}
                or assertion.get("status") != "product_observed"
                or not isinstance(assertion.get("evidence_digest"), str)
                or MULTIHASH.fullmatch(assertion["evidence_digest"]) is None
                for assertion in assertions
            )
        ):
            fail("packaged Honey demo component lacks repeated no-egress evidence")


def _runner_command(
    arguments: argparse.Namespace,
    *,
    extracted: Path,
    staged: dict[str, Path],
    report: Path,
) -> list[str]:
    command = [
        sys.executable,
        "-B",
        str(extracted / "demos/run_honey.py"),
        "--manifest",
        str(extracted / "demos/honey-manifest.v1.json"),
        "--scenario",
        FLOW_SCENARIOS[arguments.flow],
        "--runtime-archive",
        str(staged["runtime"]),
        "--runtime-sha256",
        arguments.runtime_sha256,
        "--output",
        str(report),
    ]
    if arguments.flow == "handoff":
        command.extend(
            [
                "--python-wheel",
                str(staged["python-wheel"]),
                "--python-wheel-sha256",
                arguments.python_wheel_sha256,
            ]
        )
    if arguments.flow == "claude-plugin":
        command.extend(
            [
                "--claude-plugin-archive",
                str(staged["claude-plugin"]),
                "--claude-plugin-sha256",
                arguments.claude_plugin_sha256,
            ]
        )
    return command


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    _validate_selection(arguments)
    output_relative = "/".join(safe_evidence_path(os.fspath(arguments.output)))
    with tempfile.TemporaryDirectory(prefix="cigar-honey-docs-") as raw:
        stage = Path(raw).resolve()
        artifacts = stage / "artifacts"
        artifacts.mkdir(mode=0o700)
        staged = {
            "demos": artifacts / "honey-demos.tar.gz",
            "runtime": artifacts / "runtime.tar.gz",
        }
        identities = {
            "demos": _stage_artifact(
                arguments.demos_archive,
                staged["demos"],
                arguments.demos_sha256,
                "Honey demo archive",
            ),
            "runtime": _stage_artifact(
                arguments.runtime_archive,
                staged["runtime"],
                arguments.runtime_sha256,
                "Honey runtime archive",
            ),
        }
        support: dict[str, dict[str, Any]] = {}
        if arguments.flow == "handoff":
            assert arguments.python_wheel is not None
            assert arguments.python_wheel_sha256 is not None
            staged["python-wheel"] = artifacts / "python-sdk.whl"
            support["python-wheel"] = _stage_artifact(
                arguments.python_wheel,
                staged["python-wheel"],
                arguments.python_wheel_sha256,
                "Honey Python wheel",
            )
        if arguments.flow == "claude-plugin":
            assert arguments.claude_plugin_archive is not None
            assert arguments.claude_plugin_sha256 is not None
            staged["claude-plugin"] = artifacts / "claude-plugin.tar.gz"
            support["claude-plugin"] = _stage_artifact(
                arguments.claude_plugin_archive,
                staged["claude-plugin"],
                arguments.claude_plugin_sha256,
                "Honey Claude plugin archive",
            )

        package = verify_package(
            staged["demos"],
            DEMOS_CONTRACT,
            PRODUCT_VERSION,
            CONTEXT_ABI,
        )
        metadata = package.get("metadata") if isinstance(package, dict) else None
        source = metadata.get("source") if isinstance(metadata, dict) else None
        if (
            not isinstance(metadata, dict)
            or metadata.get("artifact_id") != DEMOS_ARTIFACT_ID
            or metadata.get("contract") != DEMOS_CONTRACT_REFERENCE
            or not isinstance(source, dict)
            or source.get("committed") is not True
            or source.get("clean") is not True
        ):
            fail("demo archive is not an exact clean Honey artifact")

        extracted = stage / "demo-package"
        _extract_demos(staged["demos"], extracted)
        runner = extracted / "demos/run_honey.py"
        suite = extracted / "demos/honey-manifest.v1.json"
        if runner.is_symlink() or not runner.is_file():
            fail("verified demo archive has no packaged Honey runner")
        if suite.is_symlink() or not suite.is_file():
            fail("verified demo archive has no packaged Honey suite manifest")
        runner_report = stage / "packaged-runner-report.json"
        home = stage / "home"
        home.mkdir(mode=0o700)
        _run_packaged_runner(
            _runner_command(
                arguments,
                extracted=extracted,
                staged=staged,
                report=runner_report,
            ),
            extracted,
            home,
        )
        demo_report = _load_strict_report(runner_report)
        _validate_demo_report(
            demo_report,
            flow=arguments.flow,
            suite_sha256=hashlib.sha256(suite.read_bytes()).hexdigest(),
            source=source,
            runtime=identities["runtime"],
            support=support,
        )
        receipt: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA,
            "status": "passed",
            "product_version": PRODUCT_VERSION,
            "context_abi": CONTEXT_ABI,
            "flow": arguments.flow,
            "scenario": FLOW_SCENARIOS[arguments.flow],
            "offline": True,
            "create_new": True,
            "artifacts": {
                "honey_demos": identities["demos"],
                "runtime": identities["runtime"],
                **{
                    label.replace("-", "_"): identity
                    for label, identity in support.items()
                },
            },
            "source": _source_binding(source, demo_report.get("source")),
            "demo_report_sha256": hashlib.sha256(
                canonical_json_bytes(demo_report)
            ).hexdigest(),
            "demo_report": demo_report,
        }
        with EvidenceWorkspace.create(
            arguments.evidence_dir,
            repository_root=ROOT,
        ) as workspace:
            workspace.write_json(output_relative, receipt)
    print(f"Honey installed documentation flow passed: {arguments.flow}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        HoneyDocsQualificationError,
        OSError,
        ReleaseError,
    ) as error:
        raise SystemExit(f"honey-docs-qualification: {error}") from error
