#!/usr/bin/env python3
"""Build and verify the hol-cigar 0.9.1 PyPI developer-preview distributions."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "packaging" / "pypi"
SDK_ROOT = ROOT / "sdk" / "python"
NAME = "hol-cigar"
NORMALIZED_NAME = "hol_cigar"
IMPORT_PACKAGE = "cigar_sdk"
VERSION = "0.9.1"
CONTEXT_ABI = "cigar.context.v1"
TAG = "hol-cigar-v0.9.1-pypi.1"
SDIST = f"{NORMALIZED_NAME}-{VERSION}.tar.gz"
WHEEL = f"{NORMALIZED_NAME}-{VERSION}-py3-none-any.whl"
PROFILE_PATH = PACKAGE_ROOT / "release-profile.v1.json"
PYPROJECT_PATH = PACKAGE_ROOT / "pyproject.toml"
README_PATH = PACKAGE_ROOT / "README.md"
NOTICE_PATH = PACKAGE_ROOT / "NOTICE"
RELEASE_PATH = PACKAGE_ROOT / "release.json"
TEST_CONTRACT_PATH = PACKAGE_ROOT / "test_release_contract.py"
MANDATORY_GATES = (
    "authority-drift",
    "protocol-drift",
    "clean-committed-tagged-source",
    "focused-sdk-tests",
    "wheel-sdist-contracts",
    "wheel-sdist-clean-installs",
    "docs-rendering-and-links",
    "license-notice",
    "artifact-checksums",
)
DEFERRED_GATES = (
    "seven-day-fuzz",
    "four-hour-mutation",
    "twenty-four-hour-soak",
    "production-chaos-matrix",
    "large-scale-qualification",
    "two-builder-reproducibility",
    "production-support",
    "ga",
)
PROHIBITED_CLAIMS = (
    "production-ready",
    "production-supported",
    "production-qualified",
    "independently-security-certified",
    "ga",
)
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000


class PackageError(RuntimeError):
    """The bounded PyPI package build or verification failed."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(document, dict):
        raise PackageError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_archive_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise PackageError(f"archive contains an unsafe path: {value!r}")
    return path


def _validate_source_tree(path: Path) -> None:
    if not path.is_dir() or path.is_symlink():
        raise PackageError(f"source directory is unavailable or linked: {path}")
    for entry in path.rglob("*"):
        relative = entry.relative_to(path).as_posix()
        if entry.is_symlink():
            raise PackageError(f"source package contains a symlink: {relative}")
        if entry.is_file():
            metadata = entry.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > MAX_FILE_BYTES
            ):
                raise PackageError(f"source package file is not bounded: {relative}")


def validate_authority(root: Path = ROOT) -> dict[str, Any]:
    package_root = root / "packaging" / "pypi"
    try:
        pyproject = tomllib.loads(
            (package_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        readme = (package_root / "README.md").read_text(encoding="utf-8")
        notice = (package_root / "NOTICE").read_text(encoding="utf-8")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageError(f"cannot read PyPI package authority: {error}") from error

    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise PackageError("PyPI pyproject is missing [project]")
    expected_project = {
        "name": NAME,
        "version": VERSION,
        "description": "Python SDK for CIGAR, an open protocol developed by HOL",
        "readme": "README.md",
        "license": "Apache-2.0",
        "license-files": ["LICENSE", "NOTICE"],
        "requires-python": ">=3.14,<3.15",
        "dependencies": ["protobuf==6.33.5"],
    }
    if any(project.get(key) != value for key, value in expected_project.items()):
        raise PackageError("PyPI project identity or dependency metadata drifted")
    if project.get("scripts") != {
        "cigar-qualify-bundle": "cigar_sdk.qualify_bundle:main",
        "cigar-agent-b-handoff": "cigar_sdk.examples.agent_b_handoff:main",
    }:
        raise PackageError("PyPI console-script metadata drifted")
    if project.get("urls") != {
        "Homepage": "https://hol.org",
        "Documentation": "https://github.com/hashgraph-online/hol-cigar/tree/main/docs",
        "Issues": "https://github.com/hashgraph-online/hol-cigar/issues",
        "Repository": "https://github.com/hashgraph-online/hol-cigar",
    }:
        raise PackageError("PyPI project URL metadata drifted")
    classifiers = project.get("classifiers")
    if not isinstance(classifiers, list) or "Development Status :: 3 - Alpha" not in classifiers:
        raise PackageError("PyPI package is not classified as a developer preview")
    if pyproject.get("build-system") != {
        "requires": ["hatchling==1.28.0"],
        "build-backend": "hatchling.build",
    }:
        raise PackageError("PyPI build backend is not exactly pinned")

    release = _load_json(package_root / "release.json")
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": NAME,
        "version": VERSION,
        "release_state": "developer-preview",
        "context_abi": CONTEXT_ABI,
        "protocol_home": "https://hol.org",
    }:
        raise PackageError("PyPI SDK release identity drifted")

    profile = _load_json(package_root / "release-profile.v1.json")
    expected_profile_fields = {
        "schema_version": "cigar.pypi-release-profile.v1",
        "profile_id": "cigar.honey-equivalent.python-sdk-developer-preview.v1",
        "distribution": NAME,
        "import_package": IMPORT_PACKAGE,
        "version": VERSION,
        "context_abi": CONTEXT_ABI,
        "protocol_home": "https://hol.org",
        "release_state": "developer-preview",
        "prerelease_claim": True,
        "supported": False,
        "production_qualified": False,
        "qualification_basis": "bounded-honey-developer-preview",
    }
    if any(profile.get(key) != value for key, value in expected_profile_fields.items()):
        raise PackageError("PyPI release profile identity or claims drifted")
    if profile.get("mandatory_gates") != list(MANDATORY_GATES):
        raise PackageError("PyPI mandatory developer-preview gates drifted")
    if profile.get("deferred_full_release_gates") != list(DEFERRED_GATES):
        raise PackageError("PyPI deferred full-release gates drifted")
    if profile.get("prohibited_claims") != list(PROHIBITED_CLAIMS):
        raise PackageError("PyPI prohibited claims drifted")
    if profile.get("publication") != {
        "registry": "https://pypi.org",
        "trusted_publishing_required": True,
        "github_environment": "pypi",
        "workflow": "publish-hol-cigar.yml",
        "tag": TAG,
        "replace_artifact_bytes": False,
    }:
        raise PackageError("PyPI publication authority drifted")

    lowered = f"{readme}\n{notice}".casefold()
    for required in (
        "https://hol.org",
        "developed by hol",
        "developer preview",
        "not production-qualified",
    ):
        if required not in lowered:
            raise PackageError(f"PyPI attribution or preview warning is missing: {required}")
    return profile


def _git(root: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise PackageError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def source_identity(
    root: Path = ROOT,
    *,
    require_clean: bool = False,
    require_tag: str | None = None,
) -> dict[str, Any]:
    revision = _git(root, "rev-parse", "--verify", "HEAD")
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    clean = not status
    if require_clean and not clean:
        raise PackageError("PyPI release build requires a clean committed source tree")
    if require_tag is not None:
        tagged_revision = _git(
            root, "rev-parse", "--verify", f"refs/tags/{require_tag}^{{commit}}"
        )
        if tagged_revision != revision:
            raise PackageError(
                f"required tag {require_tag!r} does not resolve to the source revision"
            )
    return {
        "revision": revision,
        "tree": tree,
        "clean": clean,
        "tag": require_tag,
    }


def _copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise PackageError(f"required source file is unavailable or linked: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)


def stage(root: Path, destination: Path) -> None:
    if destination.exists():
        raise PackageError(f"staging destination already exists: {destination}")
    destination.mkdir(mode=0o700)
    source_package = root / "sdk" / "python" / "src" / IMPORT_PACKAGE
    source_tests = root / "sdk" / "python" / "tests"
    _validate_source_tree(source_package)
    _validate_source_tree(source_tests)

    shutil.copytree(
        source_package,
        destination / "src" / IMPORT_PACKAGE,
        copy_function=shutil.copyfile,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
    )
    shutil.copytree(
        source_tests,
        destination / "tests",
        copy_function=shutil.copyfile,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
    )
    package_root = root / "packaging" / "pypi"
    _copy_file(package_root / "pyproject.toml", destination / "pyproject.toml")
    _copy_file(package_root / "README.md", destination / "README.md")
    _copy_file(root / "sdk" / "python" / "LICENSE", destination / "LICENSE")
    _copy_file(package_root / "NOTICE", destination / "NOTICE")
    _copy_file(
        package_root / "release.json",
        destination / "src" / IMPORT_PACKAGE / "release.json",
    )
    _copy_file(
        package_root / "test_release_contract.py",
        destination / "tests" / "test_release_contract.py",
    )
    _validate_source_tree(destination)


def _metadata(payload: bytes, label: str) -> dict[str, Any]:
    try:
        message = BytesParser(policy=email_policy).parsebytes(payload)
    except Exception as error:
        raise PackageError(f"cannot parse {label} core metadata: {error}") from error
    if message.get("Name") != NAME or message.get("Version") != VERSION:
        raise PackageError(f"{label} package identity is stale")
    if message.get("Summary") != "Python SDK for CIGAR, an open protocol developed by HOL":
        raise PackageError(f"{label} package summary is stale")
    if message.get("Requires-Python") != "<3.15,>=3.14":
        raise PackageError(f"{label} Python requirement is stale")
    if message.get_all("Requires-Dist") != ["protobuf==6.33.5"]:
        raise PackageError(f"{label} dependencies are stale")
    if message.get("License-Expression") != "Apache-2.0":
        raise PackageError(f"{label} license expression is stale")
    if message.get_all("License-File") != ["LICENSE", "NOTICE"]:
        raise PackageError(f"{label} license files are stale")
    if "Development Status :: 3 - Alpha" not in message.get_all("Classifier", []):
        raise PackageError(f"{label} developer-preview classifier is missing")
    project_urls = set(message.get_all("Project-URL", []))
    expected_urls = {
        "Homepage, https://hol.org",
        "Documentation, https://github.com/hashgraph-online/hol-cigar/tree/main/docs",
        "Issues, https://github.com/hashgraph-online/hol-cigar/issues",
        "Repository, https://github.com/hashgraph-online/hol-cigar",
    }
    if project_urls != expected_urls:
        raise PackageError(f"{label} project URLs are stale")
    description = str(message.get_payload())
    lowered = description.casefold()
    if (
        "https://hol.org" not in lowered
        or "developer preview" not in lowered
        or "not production-qualified" not in lowered
    ):
        raise PackageError(f"{label} long description lost attribution or preview limits")
    return {
        "metadata_version": message.get("Metadata-Version"),
        "name": message.get("Name"),
        "version": message.get("Version"),
        "requires_python": message.get("Requires-Python"),
        "description_sha256": hashlib.sha256(description.encode()).hexdigest(),
    }


def _validate_release(payload: bytes, label: str) -> None:
    try:
        document = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackageError(f"{label} release metadata is invalid: {error}") from error
    if document != _load_json(RELEASE_PATH):
        raise PackageError(f"{label} release metadata differs from PyPI authority")


def _read_sdist(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageError("source distribution exceeds its size bound")
    prefix = f"{NORMALIZED_NAME}-{VERSION}"
    payloads: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_FILES:
            raise PackageError("source distribution exceeds its entry bound")
        for member in members:
            _safe_archive_path(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise PackageError(f"source distribution has a linked/device entry: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                raise PackageError(f"source distribution has an invalid file: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise PackageError(f"cannot read source distribution member: {member.name}")
            payload = stream.read(MAX_FILE_BYTES + 1)
            if len(payload) != member.size:
                raise PackageError(f"source distribution member changed length: {member.name}")
            payloads[member.name] = payload

    required = {
        f"{prefix}/PKG-INFO",
        f"{prefix}/README.md",
        f"{prefix}/LICENSE",
        f"{prefix}/NOTICE",
        f"{prefix}/pyproject.toml",
        f"{prefix}/src/{IMPORT_PACKAGE}/__init__.py",
        f"{prefix}/src/{IMPORT_PACKAGE}/release.json",
        f"{prefix}/src/{IMPORT_PACKAGE}/py.typed",
        f"{prefix}/tests/test_release_contract.py",
    }
    missing = required - set(payloads)
    if missing:
        raise PackageError(f"source distribution is incomplete: {sorted(missing)}")
    if any(not name.startswith(f"{prefix}/") for name in payloads):
        raise PackageError("source distribution contains a second archive root")
    _validate_release(
        payloads[f"{prefix}/src/{IMPORT_PACKAGE}/release.json"], "sdist"
    )
    metadata = _metadata(payloads[f"{prefix}/PKG-INFO"], "sdist")
    return {"file_count": len(payloads), "metadata": metadata}


def _record_digest(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return f"sha256={encoded.decode('ascii')}"


def _read_wheel(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageError("wheel exceeds its size bound")
    dist_info = f"{NORMALIZED_NAME}-{VERSION}.dist-info"
    payloads: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise PackageError("wheel exceeds its entry bound")
        for member in members:
            _safe_archive_path(member.filename)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise PackageError(f"wheel contains a symlink: {member.filename}")
            if member.is_dir():
                continue
            if member.file_size > MAX_FILE_BYTES:
                raise PackageError(f"wheel member exceeds its size bound: {member.filename}")
            payload = archive.read(member)
            if len(payload) != member.file_size:
                raise PackageError(f"wheel member changed length: {member.filename}")
            payloads[member.filename] = payload

    required = {
        f"{IMPORT_PACKAGE}/__init__.py",
        f"{IMPORT_PACKAGE}/release.json",
        f"{IMPORT_PACKAGE}/py.typed",
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/RECORD",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
    }
    missing = required - set(payloads)
    if missing:
        raise PackageError(f"wheel is incomplete: {sorted(missing)}")
    allowed_roots = {IMPORT_PACKAGE, dist_info}
    if any(PurePosixPath(name).parts[0] not in allowed_roots for name in payloads):
        raise PackageError("wheel contains an unexpected top-level path")
    if b"Tag: py3-none-any\n" not in payloads[f"{dist_info}/WHEEL"]:
        raise PackageError("wheel is not tagged as py3-none-any")
    _validate_release(payloads[f"{IMPORT_PACKAGE}/release.json"], "wheel")
    metadata = _metadata(payloads[f"{dist_info}/METADATA"], "wheel")

    record_path = f"{dist_info}/RECORD"
    try:
        rows = list(csv.reader(io.StringIO(payloads[record_path].decode("utf-8"))))
    except (UnicodeError, csv.Error) as error:
        raise PackageError(f"wheel RECORD is invalid: {error}") from error
    records = {row[0]: row[1:] for row in rows if len(row) == 3}
    if set(records) != set(payloads):
        raise PackageError("wheel RECORD inventory differs from the wheel")
    for name, payload in payloads.items():
        digest, size = records[name]
        if name == record_path:
            if digest or size:
                raise PackageError("wheel RECORD must not hash itself")
        elif digest != _record_digest(payload) or size != str(len(payload)):
            raise PackageError(f"wheel RECORD binding differs: {name}")
    return {"file_count": len(payloads), "metadata": metadata}


def verify_distributions(package_directory: Path) -> dict[str, Any]:
    expected = {SDIST, WHEEL}
    observed = {path.name for path in package_directory.iterdir() if path.is_file()}
    if observed != expected:
        raise PackageError(
            f"distribution inventory differs: expected={sorted(expected)} "
            f"observed={sorted(observed)}"
        )
    sdist = package_directory / SDIST
    wheel = package_directory / WHEEL
    sdist_report = _read_sdist(sdist)
    wheel_report = _read_wheel(wheel)
    if sdist_report["metadata"] != wheel_report["metadata"]:
        raise PackageError("wheel and source distribution metadata differ")
    return {
        "sdist": {
            "filename": SDIST,
            "sha256": _sha256(sdist),
            "bytes": sdist.stat().st_size,
            **sdist_report,
        },
        "wheel": {
            "filename": WHEEL,
            "sha256": _sha256(wheel),
            "bytes": wheel.stat().st_size,
            **wheel_report,
        },
    }


def _run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    process = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout)[-4000:].strip()
        raise PackageError(f"command failed ({' '.join(command)}): {detail}")


def _source_date_epoch(root: Path, explicit: str | None) -> int:
    raw = explicit if explicit is not None else _git(root, "show", "-s", "--format=%ct", "HEAD")
    try:
        epoch = int(raw)
    except ValueError as error:
        raise PackageError("SOURCE_DATE_EPOCH must be an integer") from error
    if epoch <= 0:
        raise PackageError("SOURCE_DATE_EPOCH must be positive")
    return epoch


def build(
    output: Path,
    *,
    root: Path = ROOT,
    uv: Path | None = None,
    require_clean: bool = False,
    require_tag: str | None = None,
    source_date_epoch: str | None = None,
    offline: bool = False,
) -> dict[str, Any]:
    profile = validate_authority(root)
    identity = source_identity(
        root, require_clean=require_clean, require_tag=require_tag
    )
    epoch = _source_date_epoch(root, source_date_epoch)
    if output.exists():
        raise PackageError(f"output path already exists: {output}")
    output.mkdir(parents=True, mode=0o700)
    package_directory = output / "packages"
    package_directory.mkdir(mode=0o700)
    executable = uv or Path(shutil.which("uv") or "")
    if not executable.is_absolute() or not executable.is_file():
        raise PackageError("uv is required and must resolve to an absolute executable")

    with tempfile.TemporaryDirectory(prefix="hol-cigar-pypi-") as temporary:
        temporary_root = Path(temporary).resolve()
        staging = temporary_root / "source"
        stage(root, staging)
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "SOURCE_DATE_EPOCH": str(epoch),
                "UV_NO_PROGRESS": "1",
            }
        )
        common = [str(executable), "build", "--no-create-gitignore"]
        if offline:
            common.append("--offline")
        _run(
            [
                *common,
                "--sdist",
                "--out-dir",
                str(package_directory),
                str(staging),
            ],
            cwd=root,
            environment=environment,
        )
        _run(
            [
                *common,
                "--wheel",
                "--out-dir",
                str(package_directory),
                str(package_directory / SDIST),
            ],
            cwd=root,
            environment=environment,
        )

    artifacts = verify_distributions(package_directory)
    checksum_lines = [
        f"{artifacts[kind]['sha256']}  packages/{artifacts[kind]['filename']}"
        for kind in ("sdist", "wheel")
    ]
    checksum_payload = ("\n".join(checksum_lines) + "\n").encode()
    checksum_path = output / "SHA256SUMS"
    checksum_path.write_bytes(checksum_payload)
    os.chmod(checksum_path, 0o400)
    for artifact in package_directory.iterdir():
        os.chmod(artifact, 0o400)

    receipt = {
        "schema_version": "cigar.pypi-build-receipt.v1",
        "profile_id": profile["profile_id"],
        "distribution": NAME,
        "version": VERSION,
        "release_state": "developer-preview",
        "context_abi": CONTEXT_ABI,
        "protocol_home": "https://hol.org",
        "source": identity,
        "source_date_epoch": epoch,
        "artifacts": artifacts,
        "checksums": {
            "filename": "SHA256SUMS",
            "sha256": hashlib.sha256(checksum_payload).hexdigest(),
        },
        "gates": {
            gate: "passed" if gate not in {
                "clean-committed-tagged-source",
                "focused-sdk-tests",
                "protocol-drift",
                "wheel-sdist-clean-installs",
            } else "required-external"
            for gate in MANDATORY_GATES
        },
        "claims": {
            "developer_preview": True,
            "supported": False,
            "production_qualified": False,
            "full_release_qualified": False,
        },
        "status": "built-and-structurally-verified",
    }
    if require_clean and require_tag is not None:
        receipt["gates"]["clean-committed-tagged-source"] = "passed"
    receipt_path = output / "build-receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(receipt_path, 0o400)
    return receipt


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--uv", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-tag")
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--offline", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        receipt = build(
            arguments.out.resolve(),
            root=arguments.root.resolve(),
            uv=arguments.uv.resolve() if arguments.uv else None,
            require_clean=arguments.require_clean,
            require_tag=arguments.require_tag,
            source_date_epoch=arguments.source_date_epoch,
            offline=arguments.offline,
        )
    except (OSError, PackageError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
