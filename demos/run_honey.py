#!/usr/bin/env python3
"""Run the four Honey stories twice from supplied installed release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Never, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "demos"
RELEASE_TOOLS = ROOT / "scripts" / "release"
for import_root in (DEMO_ROOT, RELEASE_TOOLS):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)


def _load(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("Honey demo dependency is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


demo_runner = _load("cigar_honey_source_demo_runner", DEMO_ROOT / "run.py")
installed = _load(
    "cigar_honey_installed_artifact_support",
    DEMO_ROOT / "installed_artifact_test.py",
)

SUITE_SCHEMA = "cigar.honey-demo-suite.v1"
REPORT_SCHEMA = "cigar.honey-installed-demo-report.v1"
PRODUCT_VERSION = "0.9.0-honey.1"
CONTEXT_ABI = "cigar.context.v1"
EVIDENCE_CLASS = "cigar.honey-installed-demo.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
RUNTIME_FILES = {
    "LICENSE",
    "NOTICE",
    "RELEASE-METADATA.json",
    "SHA256SUMS",
    "bin/cigar",
    "bin/cigard",
    "bin/cigar-claude-hook",
    "bin/cigar-mcp",
    "completions/_cigar",
    "completions/cigar.bash",
    "completions/cigar.fish",
    "share/man/man1/cigar.1",
}
EXECUTABLES = {
    "cigar": "bin/cigar",
    "cigard": "bin/cigard",
    "hook": "bin/cigar-claude-hook",
    "mcp": "bin/cigar-mcp",
}


class HoneyDemoError(Exception):
    """Bounded, content-free Honey demo failure."""


def fail(message: str) -> Never:
    raise HoneyDemoError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise HoneyDemoError("Honey report cannot be canonicalized") from error


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def multihash(payload: bytes) -> str:
    return "1220" + sha256_bytes(payload)


def load_object(path: Path, maximum: int = 8 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        fail("Honey JSON input must be a bounded regular file")
    try:
        value = json.loads(
            path.read_bytes(), object_pairs_hook=demo_runner.reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HoneyDemoError("Honey JSON input is malformed") from error
    if not isinstance(value, dict):
        fail("Honey JSON input must be an object")
    return value


def artifact_identity(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    if not SHA256.fullmatch(expected_sha256):
        fail(f"{label} expected SHA-256 is malformed")
    try:
        before = path.lstat()
    except OSError as error:
        raise HoneyDemoError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > installed.MAX_ARTIFACT
    ):
        fail(f"{label} must be a bounded regular non-linked file")
    observed = installed.digest(path).removeprefix("1220")
    after = path.lstat()
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        fail(f"{label} changed while it was hashed")
    if observed != expected_sha256:
        fail(f"{label} SHA-256 does not match the independently supplied value")
    return {"sha256": observed, "bytes": before.st_size}


def regular_files(root: Path) -> set[str]:
    result: set[str] = set()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            fail("installed artifact contains a link")
        if path.is_dir():
            continue
        if not path.is_file():
            fail("installed artifact contains a special file")
        result.add(path.relative_to(root).as_posix())
    return result


def verify_internal_checksums(root: Path) -> None:
    checksum_path = root / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise HoneyDemoError(
            "runtime internal checksum manifest is unreadable"
        ) from error
    expected_paths = sorted(
        RUNTIME_FILES - {"RELEASE-METADATA.json", "SHA256SUMS"},
        key=lambda value: value.encode("utf-8"),
    )
    parsed: list[tuple[str, str]] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if match is None:
            fail("runtime internal checksum manifest is malformed")
        parsed.append((match.group(1), match.group(2)))
    if [path for _digest, path in parsed] != expected_paths:
        fail("runtime internal checksum inventory is incomplete or reordered")
    for expected, relative in parsed:
        if sha256_bytes((root / relative).read_bytes()) != expected:
            fail("runtime internal checksum verification failed")


def install_runtime(
    archive: Path, expected_sha256: str, destination: Path
) -> tuple[dict[str, Any], dict[str, Path], dict[str, Any]]:
    identity = artifact_identity(archive, expected_sha256, "runtime archive")
    destination.mkdir(mode=0o700)
    installed.unpack(archive, destination)
    if regular_files(destination) != RUNTIME_FILES:
        fail("runtime archive does not contain the exact Honey member inventory")
    verify_internal_checksums(destination)
    metadata = load_object(destination / "RELEASE-METADATA.json")
    source = metadata.get("source")
    if (
        metadata.get("schema_version") != "cigar.release-metadata.v1"
        or metadata.get("product_version") != PRODUCT_VERSION
        or metadata.get("context_abi") != CONTEXT_ABI
        or not isinstance(source, dict)
        or not REVISION.fullmatch(str(source.get("revision", "")))
        or not SHA256.fullmatch(str(source.get("tree_sha256", "")))
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        fail("runtime release metadata is not an exact clean Honey source binding")
    binaries = {name: destination / relative for name, relative in EXECUTABLES.items()}
    for binary in binaries.values():
        binary.chmod(0o700)
        if not os.access(binary, os.X_OK):
            fail("runtime executable could not be made owner-executable")
    probe_home = destination / ".version-probe"
    probe_home.mkdir(mode=0o700)
    completed = installed.run(
        [str(binaries["cigar"]), "--output", "json", "version"],
        destination,
        probe_home,
        60,
    )
    try:
        version = json.loads(
            completed.stdout,
            object_pairs_hook=demo_runner.reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HoneyDemoError("installed runtime version output is malformed") from error
    if (
        not isinstance(version, dict)
        or version.get("version") != PRODUCT_VERSION
        or version.get("context_abi") != CONTEXT_ABI
        or version.get("source_revision") != source["revision"]
        or version.get("build_profile") != "release"
    ):
        fail("installed runtime executable identity does not match release metadata")
    probe_home.rmdir()
    return identity, binaries, metadata


def install_python_wheel(
    wheel: Path, expected_sha256: str, destination: Path
) -> tuple[dict[str, Any], Path]:
    identity = artifact_identity(wheel, expected_sha256, "Python wheel")
    destination.mkdir(mode=0o700)
    installed.unpack(wheel, destination)
    release_files = list(destination.glob("cigar_sdk/release.json"))
    if len(release_files) != 1:
        fail("Python wheel has no unique SDK release identity")
    release = load_object(release_files[0])
    if (
        release.get("version") != PRODUCT_VERSION
        or release.get("context_abi") != CONTEXT_ABI
    ):
        fail("Python wheel identity does not match Honey")
    return identity, destination


def install_plugin(
    archive: Path,
    expected_sha256: str,
    destination: Path,
    binaries: dict[str, Path],
    source: dict[str, Any],
) -> tuple[dict[str, Any], Path]:
    identity = artifact_identity(archive, expected_sha256, "Claude plugin archive")
    destination.mkdir(mode=0o700)
    installed.unpack(archive, destination)
    manifests = list(destination.rglob(".claude-plugin/plugin.json"))
    if len(manifests) != 1:
        fail("Claude archive has no unique plugin root")
    plugin_root = manifests[0].parent.parent
    plugin = load_object(manifests[0])
    compatibility = load_object(plugin_root / "compatibility.json")
    metadata = load_object(plugin_root / "RELEASE-METADATA.json")
    plugin_source = metadata.get("source")
    if (
        plugin.get("version") != PRODUCT_VERSION
        or compatibility.get("context_abi") != CONTEXT_ABI
        or metadata.get("product_version") != PRODUCT_VERSION
        or not isinstance(plugin_source, dict)
        or plugin_source.get("revision") != source.get("revision")
        or not SHA256.fullmatch(str(plugin_source.get("tree_sha256", "")))
        or plugin_source.get("committed") is not True
        or plugin_source.get("clean") is not True
    ):
        fail("Claude plugin identity does not match the Honey runtime")
    for name, runtime_name in (("cigar-mcp", "mcp"), ("cigar-claude-hook", "hook")):
        packaged = plugin_root / "bin" / name
        if not packaged.is_file() or packaged.is_symlink():
            fail("Claude plugin is missing a bound runtime executable")
        if sha256_bytes(packaged.read_bytes()) != sha256_bytes(
            binaries[runtime_name].read_bytes()
        ):
            fail("Claude plugin runtime bytes differ from the installed runtime")
    identity["source"] = plugin_source
    return identity, plugin_root


def load_suite(
    path: Path,
) -> tuple[dict[str, Any], dict[str, list[tuple[Path, dict[str, Any]]]]]:
    suite = load_object(path)
    if set(suite) != {
        "schema_version",
        "product_version",
        "context_abi",
        "evidence_class",
        "runs_per_scenario",
        "network_required",
        "credentials_required",
        "scenarios",
    }:
        fail("Honey demo suite fields do not match v1")
    if (
        suite.get("schema_version") != SUITE_SCHEMA
        or suite.get("product_version") != PRODUCT_VERSION
        or suite.get("context_abi") != CONTEXT_ABI
        or suite.get("evidence_class") != EVIDENCE_CLASS
        or suite.get("runs_per_scenario") != 2
        or suite.get("network_required") is not False
        or suite.get("credentials_required") is not False
    ):
        fail("Honey demo suite authority is stale")
    scenarios = suite.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 4:
        fail("Honey demo suite must contain exactly four stories")
    loaded: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    expected = {"offline-context", "two-agent", "effect-recovery-replay", "claude-mcp"}
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != {
            "id",
            "title",
            "components",
        }:
            fail("Honey demo scenario fields do not match v1")
        identifier = scenario.get("id")
        components = scenario.get("components")
        if (
            identifier not in expected
            or identifier in loaded
            or not isinstance(scenario.get("title"), str)
            or not isinstance(components, list)
            or not components
        ):
            fail("Honey demo scenario inventory is malformed")
        loaded_components: list[tuple[Path, dict[str, Any]]] = []
        for relative in components:
            if not isinstance(relative, str):
                fail("Honey demo component path is malformed")
            candidate = ROOT / relative
            resolved = candidate.resolve()
            if ROOT not in resolved.parents or candidate.is_symlink():
                fail("Honey demo component path escapes the source tree")
            manifest = demo_runner.validate_manifest(
                demo_runner.load_json(resolved), resolved
            )
            loaded_components.append((resolved, manifest))
        loaded[identifier] = loaded_components
    if set(loaded) != expected:
        fail("Honey demo story identifiers are incomplete")
    return suite, loaded


def run_component_once(
    manifest_path: Path,
    manifest: dict[str, Any],
    binaries: dict[str, Path],
    registry: dict[str, bytes],
    python_root: Path | None,
    plugin_root: Path | None,
) -> dict[str, Any]:
    fixture_path = manifest_path.parent / manifest["fixture"]
    fixture = demo_runner.load_json(fixture_path)
    if len(manifest["canary_ids"]) != 1 or fixture.get("secret_canary") != registry[
        manifest["canary_ids"][0]
    ].decode("utf-8"):
        fail("Honey component canary binding is stale")
    with tempfile.TemporaryDirectory(prefix="cigar-honey-installed-demo-") as raw:
        state = Path(raw).resolve()
        command = [
            sys.executable,
            str(manifest_path.parent / manifest["driver"]),
            "--fixture",
            str(fixture_path),
            "--state",
            str(state),
            "--cigar-binary",
            str(binaries["cigar"]),
        ]
        if manifest["demo_id"] == "claude-code-experience":
            if plugin_root is None:
                fail("Claude story requires the exact plugin archive")
            command.extend(["--hook-binary", str(binaries["hook"])])
        if manifest["demo_id"] == "honey-two-agent-handoff" and python_root is None:
            fail("two-agent story requires the exact Python wheel")
        command, enforcement = demo_runner.sandboxed_driver_command(command)
        if enforcement == "unavailable":
            fail("Honey installed demos require the macOS no-egress boundary")
        environment = demo_runner.clean_environment(state)
        environment["CIGAR_DEMO_NO_EGRESS"] = enforcement
        if python_root is not None:
            environment["CIGAR_DEMO_PYTHON_SDK_ROOT"] = str(python_root)
        if plugin_root is not None:
            environment["CIGAR_DEMO_CLAUDE_PLUGIN_ROOT"] = str(plugin_root)
        payload = demo_runner.run_bounded_process(
            command,
            state,
            registry,
            timeout=300,
            environment=environment,
        )
        try:
            value = json.loads(payload, object_pairs_hook=demo_runner.reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HoneyDemoError("Honey component returned malformed JSON") from error
        result = demo_runner.validate_driver_result(
            value, fixture_path, fixture, manifest
        )
        if result["no_egress_enforcement"] != enforcement:
            fail("Honey component disagrees with its no-egress boundary")
        demo_runner.scan_tree(state, registry)
    if not demo_runner.driver_release_qualified(result):
        fail("Honey installed component did not observe every public assertion")
    return result


def run_story(
    identifier: str,
    components: Sequence[tuple[Path, dict[str, Any]]],
    binaries: dict[str, Path],
    registry: dict[str, bytes],
    python_root: Path | None,
    plugin_root: Path | None,
) -> dict[str, Any]:
    component_reports: list[dict[str, Any]] = []
    for manifest_path, manifest in components:
        first = run_component_once(
            manifest_path, manifest, binaries, registry, python_root, plugin_root
        )
        second = run_component_once(
            manifest_path, manifest, binaries, registry, python_root, plugin_root
        )
        if first["result_digest"] != second["result_digest"]:
            fail("Honey repeated component produced a different semantic identity")
        component_reports.append(
            {
                "demo_id": manifest["demo_id"],
                "fixed_seed": manifest["fixed_seed"],
                "manifest_digest": multihash(manifest_path.read_bytes()),
                "fixture_digest": manifest["fixture_digest"],
                "driver_digest": manifest["driver_digest"],
                "driver_support_digest": manifest["driver_support_digest"],
                "semantic_identity": first["result_digest"],
                "repeated_semantic_identity": second["result_digest"],
                "no_egress_enforcement": first["no_egress_enforcement"],
                "assertions": first["assertions"],
                "status": "installed_component_passed_twice",
            }
        )
    story_identity = multihash(
        canonical(
            [
                {
                    "demo_id": component["demo_id"],
                    "semantic_identity": component["semantic_identity"],
                }
                for component in component_reports
            ]
        )
    )
    return {
        "scenario_id": identifier,
        "status": "installed_story_passed_twice",
        "semantic_identity": story_identity,
        "components": component_reports,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=DEMO_ROOT / "honey-manifest.v1.json"
    )
    parser.add_argument("--scenario", action="append")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--runtime-archive", type=Path)
    parser.add_argument("--runtime-sha256")
    parser.add_argument("--python-wheel", type=Path)
    parser.add_argument("--python-wheel-sha256")
    parser.add_argument("--claude-plugin-archive", type=Path)
    parser.add_argument("--claude-plugin-sha256")
    parser.add_argument("--output", type=Path, default=Path("honey-demo-report.json"))
    parser.add_argument("--evidence-dir", type=Path)
    return parser.parse_args(argv)


def publish(arguments: argparse.Namespace, report: dict[str, Any]) -> None:
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if arguments.evidence_dir is not None and environment:
        if os.fspath(arguments.evidence_dir) != environment:
            fail("--evidence-dir conflicts with CIGAR_EVIDENCE_DIR")
    selected = arguments.evidence_dir or (Path(environment) if environment else None)
    if selected is not None:
        if not selected.is_absolute() or arguments.output.is_absolute():
            fail(
                "protected Honey evidence requires an absolute root and relative output"
            )
        relative = "/".join(safe_evidence_path(os.fspath(arguments.output)))
        workspace = EvidenceWorkspace.create(selected, repository_root=ROOT)
        try:
            workspace.write_json(relative, report)
        finally:
            workspace.close()
        return
    output = arguments.output.resolve()
    if output.exists() or output.is_symlink():
        fail("refusing to overwrite a Honey demo report")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(report) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.chmod(output, 0o400)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    suite_path = arguments.manifest.resolve()
    suite, scenarios = load_suite(suite_path)
    selected = arguments.scenario or list(scenarios)
    if len(set(selected)) != len(selected) or any(
        item not in scenarios for item in selected
    ):
        fail("Honey scenario selection is duplicated or unknown")
    if arguments.list:
        for identifier in scenarios:
            print(identifier)
        return 0
    suite_binding = {
        "manifest": suite_path.relative_to(ROOT).as_posix(),
        "sha256": sha256_bytes(suite_path.read_bytes()),
    }
    if arguments.validate_only:
        report: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA,
            "status": "validation_only",
            "product_version": PRODUCT_VERSION,
            "context_abi": CONTEXT_ABI,
            "evidence_class": EVIDENCE_CLASS,
            "suite": suite_binding,
            "selected_scenarios": selected,
            "runtime": None,
            "source": None,
            "supporting_artifacts": {},
            "scenarios": [],
            "installed_artifact_qualified": False,
        }
        report["report_digest"] = multihash(canonical(report))
        publish(arguments, report)
        return 0
    if arguments.runtime_archive is None or arguments.runtime_sha256 is None:
        fail("installed Honey demos require a runtime archive and independent SHA-256")
    requires_python = "two-agent" in selected
    requires_plugin = "claude-mcp" in selected
    if requires_python and (
        arguments.python_wheel is None or arguments.python_wheel_sha256 is None
    ):
        fail(
            "the selected two-agent story requires a Python wheel and independent SHA-256"
        )
    if requires_plugin and (
        arguments.claude_plugin_archive is None
        or arguments.claude_plugin_sha256 is None
    ):
        fail(
            "the selected Claude story requires a plugin archive and independent SHA-256"
        )
    registry = demo_runner.canaries()
    with tempfile.TemporaryDirectory(prefix="cigar-honey-installed-suite-") as raw:
        stage = Path(raw).resolve()
        runtime_identity, binaries, metadata = install_runtime(
            arguments.runtime_archive.resolve(),
            arguments.runtime_sha256,
            stage / "runtime",
        )
        supporting: dict[str, Any] = {}
        python_root: Path | None = None
        plugin_root: Path | None = None
        if requires_python:
            assert arguments.python_wheel is not None
            assert arguments.python_wheel_sha256 is not None
            python_identity, python_root = install_python_wheel(
                arguments.python_wheel.resolve(),
                arguments.python_wheel_sha256,
                stage / "python-wheel",
            )
            supporting["python_wheel"] = python_identity
        if requires_plugin:
            assert arguments.claude_plugin_archive is not None
            assert arguments.claude_plugin_sha256 is not None
            plugin_identity, plugin_root = install_plugin(
                arguments.claude_plugin_archive.resolve(),
                arguments.claude_plugin_sha256,
                stage / "claude-plugin",
                binaries,
                metadata["source"],
            )
            supporting["claude_plugin"] = plugin_identity
        story_reports = [
            run_story(
                identifier,
                scenarios[identifier],
                binaries,
                registry,
                python_root,
                plugin_root,
            )
            for identifier in selected
        ]
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "installed_demo_passed",
        "product_version": PRODUCT_VERSION,
        "context_abi": CONTEXT_ABI,
        "evidence_class": suite["evidence_class"],
        "suite": suite_binding,
        "selected_scenarios": selected,
        "runtime": runtime_identity,
        "source": metadata["source"],
        "supporting_artifacts": supporting,
        "scenarios": story_reports,
        "installed_artifact_qualified": len(story_reports) == len(selected),
    }
    report["report_digest"] = multihash(canonical(report))
    publish(arguments, report)
    print(
        f"Honey installed demos passed: {len(story_reports)} stories, two clean runs each"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        HoneyDemoError,
        installed.InstallError,
        OSError,
    ) as error:
        raise SystemExit(f"honey-demo: {error}") from error
