#!/usr/bin/env python3
"""Install, exercise, and uninstall one verified binary archive as an unprivileged offline user."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from release_lib import ReleaseError, load_json_bytes, process_failure_summary, require_distinct_output, run_bounded, safe_relative_path, sha256_bytes, sha256_file, write_json
from verify_package import verify as verify_package


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--qualification-driver", type=Path, required=True)
    parser.add_argument("--expected-artifact-id", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-version", default="0.1.0")
    parser.add_argument("--expected-abi", default="cigar.context.v1")
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def _destination(root: Path, relative: str) -> Path:
    relative = safe_relative_path(relative)
    destination = root.joinpath(*relative.split("/"))
    resolved_parent = destination.parent.resolve()
    root_resolved = root.resolve()
    if resolved_parent != root_resolved and root_resolved not in resolved_parent.parents:
        raise ReleaseError(f"archive extraction escapes install root: {relative}")
    return destination


def _extract(archive_path: Path, destination: Path) -> None:
    if archive_path.name.lower().endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path, "r:*") as archive:
            for tar_member in archive:
                if tar_member.isdir():
                    continue
                if not tar_member.isfile():
                    raise ReleaseError(f"non-regular install member: {tar_member.name}")
                output = _destination(destination, tar_member.name)
                output.parent.mkdir(parents=True, exist_ok=True)
                handle = archive.extractfile(tar_member)
                if handle is None:
                    raise ReleaseError(f"cannot read install member: {tar_member.name}")
                with handle, output.open("xb") as target:
                    shutil.copyfileobj(handle, target, 1024 * 1024)
                os.chmod(output, tar_member.mode & 0o777)
        return
    with zipfile.ZipFile(archive_path) as archive:
        for zip_member in archive.infolist():
            if zip_member.is_dir():
                continue
            mode = (zip_member.external_attr >> 16) & 0o177777
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise ReleaseError(f"linked install member: {zip_member.filename}")
            output = _destination(destination, zip_member.filename)
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(zip_member) as source, output.open("xb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            os.chmod(output, (mode & 0o777) or 0o644)


def _run(command: list[str], cwd: Path, environment: dict[str, str], expected: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = run_bounded(command, cwd=cwd, env=environment, timeout=300, max_stdout=8 * 1024 * 1024, max_stderr=8 * 1024 * 1024)
    if result.returncode != expected:
        raise ReleaseError(process_failure_summary(result, "installed command"))
    return result


def _is_administrator() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    import ctypes

    return bool(getattr(ctypes, "windll").shell32.IsUserAnAdmin())


def _host_target() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    architecture = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if system == "linux":
        libc_name = platform.libc_ver()[0].lower()
        if libc_name not in {"glibc", "gnu libc"}:
            raise ReleaseError(f"the binary matrix requires GNU libc, found {libc_name or 'unknown libc'}")
        return f"{architecture}-unknown-linux-gnu"
    if system == "darwin":
        return f"{architecture}-apple-darwin"
    if system == "windows":
        return f"{architecture}-pc-windows-msvc"
    raise ReleaseError(f"unsupported qualification host: {system}-{architecture}")


def _validate_driver_receipt(
    payload: bytes,
    artifact_id: str,
    artifact_sha256: str,
    product_version: str,
    context_abi: str,
) -> tuple[dict[str, object], list[str]]:
    receipt = load_json_bytes(payload, "installed qualification driver")
    required_keys = {"schema_version", "status", "artifact_id", "artifact_sha256", "product_version", "context_abi", "checks"}
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise ReleaseError("installed qualification driver returned an unexpected receipt shape")
    if (
        receipt.get("schema_version") != "cigar.installed-driver.v1"
        or receipt.get("status") != "passed"
        or receipt.get("artifact_id") != artifact_id
        or receipt.get("artifact_sha256") != artifact_sha256
        or receipt.get("product_version") != product_version
        or receipt.get("context_abi") != context_abi
    ):
        raise ReleaseError("installed qualification driver receipt is stale or bound to another artifact")
    checks = receipt.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ReleaseError("installed qualification driver returned no checks")
    check_ids: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"id", "status"} or check.get("status") != "passed":
            raise ReleaseError("installed qualification driver returned a malformed or non-passing check")
        identifier = check.get("id")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", identifier) is None
            or len(identifier.encode("utf-8")) > 128
        ):
            raise ReleaseError("installed qualification driver returned an invalid check id")
        check_ids.append(identifier)
    if len(set(check_ids)) != len(check_ids):
        raise ReleaseError("installed qualification driver returned duplicate check ids")
    required_checks = {
        "doctor", "init", "source-add", "ingest", "compile", "explain", "handoff",
        "effect-recovery", "replay", "daemon-lifecycle", "offline-restart", "upgrade",
    }
    if os.name == "nt":
        required_checks.add("read-only-parent")
    missing = required_checks - set(check_ids)
    if missing:
        raise ReleaseError(f"installed qualification driver omitted checks: {sorted(missing)}")
    return receipt, check_ids


def main() -> int:
    arguments = parse_arguments()
    archive = arguments.archive.resolve()
    contract = arguments.contract.resolve()
    driver = arguments.qualification_driver.resolve()
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", arguments.expected_artifact_id) is None:
        raise ReleaseError("expected artifact id is invalid")
    if re.fullmatch(r"[a-z0-9_]+-[a-z0-9_.-]+", arguments.expected_target) is None:
        raise ReleaseError("expected target triple is invalid")
    if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", arguments.expected_version) is None:
        raise ReleaseError("expected product version is invalid")
    if arguments.expected_abi != "cigar.context.v1":
        raise ReleaseError("expected Context ABI is invalid")
    if arguments.report is not None:
        require_distinct_output(arguments.report.resolve(), [archive, contract, driver], "install qualification")
    if _is_administrator():
        raise ReleaseError("install qualification must run as an unprivileged user")
    if not driver.is_file() or driver.is_symlink() or not os.access(driver, os.X_OK):
        raise ReleaseError("qualification driver must be an explicit regular executable")
    if os.environ.get("CIGAR_NO_EGRESS_ENFORCED") != "1":
        raise ReleaseError("the runner must enforce no egress and set CIGAR_NO_EGRESS_ENFORCED=1")
    target = _host_target()
    if target != arguments.expected_target:
        raise ReleaseError(f"qualification host target {target} does not match expected target {arguments.expected_target}")
    original_digest = sha256_file(archive)
    original_size = archive.stat().st_size
    driver_digest = sha256_file(driver)

    with tempfile.TemporaryDirectory(prefix="CIGAR install – café – ") as temporary:
        base = Path(temporary)
        staged_directory = base / "immutable candidate"
        staged_directory.mkdir()
        staged_archive = staged_directory / archive.name
        shutil.copyfile(archive, staged_archive)
        staged_driver = staged_directory / f"qualification-driver{driver.suffix}"
        shutil.copyfile(driver, staged_driver)
        os.chmod(staged_driver, 0o500)
        if (
            sha256_file(staged_archive) != original_digest
            or staged_archive.stat().st_size != original_size
            or sha256_file(archive) != original_digest
            or archive.stat().st_size != original_size
            or sha256_file(staged_driver) != driver_digest
        ):
            raise ReleaseError("candidate archive or qualification driver changed while it was staged")
        verification = verify_package(staged_archive, contract, arguments.expected_version, arguments.expected_abi)
        metadata = verification.get("metadata")
        source = metadata.get("source") if isinstance(metadata, dict) else None
        if (
            not isinstance(metadata, dict)
            or metadata.get("artifact_id") != arguments.expected_artifact_id
            or metadata.get("product_version") != arguments.expected_version
            or metadata.get("context_abi") != arguments.expected_abi
            or not isinstance(source, dict)
            or source.get("committed") is not True
            or source.get("clean") is not True
            or not isinstance(source.get("revision"), str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]) is None
        ):
            raise ReleaseError("binary archive metadata is not bound to the expected committed, clean candidate")
        long_path = base / "path with spaces" / "δοκιμή" / ("long-segment-" * 10) / ("nested-segment-" * 10)
        install = long_path / "prefix"
        workspace = long_path / "retained project state"
        install.mkdir(parents=True)
        workspace.mkdir(parents=True)
        marker = workspace / "retention-marker"
        marker.write_text("retain\n", encoding="utf-8")
        _extract(staged_archive, install)
        suffix = ".exe" if os.name == "nt" else ""
        cigar = install / "bin" / f"cigar{suffix}"
        cigard = install / "bin" / f"cigard{suffix}"
        if not cigar.is_file() or not cigard.is_file():
            raise ReleaseError("binary archive did not install cigar and cigard")
        binary_digests = {"cigar": sha256_file(cigar), "cigard": sha256_file(cigard)}

        environment = {
            "PATH": str(install / "bin"),
            "HOME": str(base / "empty-home"),
            "USERPROFILE": str(base / "empty-home"),
            "TMPDIR": str(base / "tmp"),
            "TMP": str(base / "tmp"),
            "TEMP": str(base / "tmp"),
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "NO_COLOR": "1",
            "CIGAR_NO_EGRESS_ENFORCED": "1",
        }
        if os.name == "nt":
            for key in ("SYSTEMROOT", "WINDIR"):
                if value := os.environ.get(key):
                    environment[key] = value
        Path(environment["HOME"]).mkdir()
        Path(environment["TMPDIR"]).mkdir()
        if shutil.which("cargo", path=environment["PATH"]) or shutil.which("rustc", path=environment["PATH"]) or shutil.which("cc", path=environment["PATH"]):
            raise ReleaseError("compiler is visible in qualification PATH")
        version_result = _run([str(cigar), "--output", "json", "version"], workspace, environment)
        version_output = load_json_bytes(version_result.stdout, "installed cigar version")
        if not isinstance(version_output, dict) or version_output.get("version") != arguments.expected_version:
            raise ReleaseError("installed cigar reports the wrong semantic version")
        _run([str(cigar), "help"], workspace, environment)

        readonly = base / "read-only-parent"
        readonly.mkdir()
        os.chmod(readonly, 0o555)
        try:
            _run([str(cigar), "version"], readonly, environment)
        finally:
            os.chmod(readonly, 0o755)

        driver_result = _run(
            [
                str(staged_driver), "--cigar", str(cigar), "--cigard", str(cigard),
                "--workspace", str(workspace), "--artifact-id", arguments.expected_artifact_id,
                "--artifact-sha256", original_digest, "--product-version", arguments.expected_version,
                "--context-abi", arguments.expected_abi,
            ],
            workspace,
            environment,
        )
        _, driver_checks = _validate_driver_receipt(
            driver_result.stdout,
            arguments.expected_artifact_id,
            original_digest,
            arguments.expected_version,
            arguments.expected_abi,
        )
        if (
            sha256_file(staged_archive) != original_digest
            or sha256_file(staged_driver) != driver_digest
            or sha256_file(cigar) != binary_digests["cigar"]
            or sha256_file(cigard) != binary_digests["cigard"]
        ):
            raise ReleaseError("candidate archive, qualification driver, or installed binary changed during qualification")

        shutil.rmtree(install)
        uninstalled = not install.exists()
        retained = marker.read_text(encoding="utf-8") == "retain\n"
        if not uninstalled or not retained:
            raise ReleaseError("uninstall removed retained state or left installed files")
        report = {
            "schema_version": "cigar.install-qualification.v1",
            "status": "passed",
            "artifact_id": arguments.expected_artifact_id,
            "artifact_sha256": original_digest,
            "artifact_bytes": original_size,
            "product_version": arguments.expected_version,
            "context_abi": arguments.expected_abi,
            "source_revision": source["revision"],
            "target": target,
            "qualification_driver": {"name": driver.name, "sha256": driver_digest},
            "driver_receipt_sha256": sha256_bytes(driver_result.stdout),
            "installed_binary_sha256": binary_digests,
            "unprivileged": True,
            "no_compiler_path": True,
            "no_egress": True,
            "path_cases": ["spaces", "unicode", "long", "read-only-parent", "non-admin"],
            "checks": sorted({"version", "help", *driver_checks}),
            "uninstalled": uninstalled,
            "state_retained": retained,
            "package_contract_sha256": verification["contract"]["sha256"],
        }
    if arguments.report is not None:
        write_json(arguments.report.resolve(), report)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"install qualification failed: {error}") from error
