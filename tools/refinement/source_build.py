"""Build three profile-bound CIGARBench adapters from exact CIGAR sources."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, identity, load_file, multihash_bytes
from .commands import CommandError, sanitized_environment
from .schema import SchemaRegistry

PLAN_SCHEMA = "honey-evaluation-plan-v1.schema.json"
BUILD_SCHEMA = "source-consumer-build-set-v1.schema.json"
SOURCE_ROLES = (
    ("published-honey", "published_honey"),
    ("champion", "champion"),
    ("candidate", "candidate"),
)
PATH_DEPENDENCIES = (
    "cigar-api",
    "cigar-canon",
    "cigar-catalog",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-crypto",
    "cigar-daemon",
    "cigar-effects",
    "cigar-policy",
    "cigar-protocol",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-space",
    "cigar-store",
)
REGISTRY_DEPENDENCIES = (
    'base64 = "=0.22.1"',
    'serde = { version = "=1.0.228", features = ["derive"] }',
    'serde_json = "=1.0.150"',
    'sha2 = "=0.11.0"',
    'tempfile = "=3.27.0"',
    'tokio = { version = "=1.52.3", features = ["macros", "rt-multi-thread"] }',
    'unicode-normalization = "=0.1.25"',
)


class SourceBuildError(RuntimeError):
    """An exact-source consumer build failed closed."""


def _canonical_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise SourceBuildError(f"{label} must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SourceBuildError(f"{label} is unavailable") from error
    if resolved != path or not path.is_dir():
        raise SourceBuildError(f"{label} must be a canonical directory")
    return resolved


def _sha256(path: Path, *, maximum_bytes: int = 1024 * 1024 * 1024) -> str:
    before = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= maximum_bytes
    ):
        raise SourceBuildError("build artifact metadata is unsafe")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = path.stat(follow_symlinks=False)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise SourceBuildError("build artifact changed while it was hashed")
    return digest


def _tool(path: str, environment: dict[str, str]) -> tuple[str, str]:
    selected = shutil.which(path, path=environment.get("PATH"))
    if selected is None:
        raise SourceBuildError(f"{path} is unavailable")
    invocation = Path(selected).absolute()
    resolved = invocation.resolve(strict=True)
    if (
        not invocation.is_file()
        or not resolved.is_file()
        or not os.access(invocation, os.X_OK)
    ):
        raise SourceBuildError(f"{path} executable is unsafe")
    return os.fspath(invocation), _sha256(resolved)


def _run(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SourceBuildError("exact-source build command failed") from error
    if len(completed.stdout) + len(completed.stderr) > 16 * 1024 * 1024:
        raise SourceBuildError("exact-source build output exceeded its bound")
    return completed.stdout


def _git_source(git: str, root: Path) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    revision = (
        _run(
            [git, "-C", os.fspath(root), "rev-parse", "HEAD^{commit}"],
            cwd=root,
            environment=environment,
            timeout=120,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    tree = (
        _run(
            [git, "-C", os.fspath(root), "rev-parse", "HEAD^{tree}"],
            cwd=root,
            environment=environment,
            timeout=120,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    return {"revision": revision, "tree": tree}


def _adapter_manifest(
    source_role: str,
    intelligence_profile: str = "balanced.v1",
    *,
    harness_role: str | None = None,
) -> bytes:
    if source_role not in {role for role, _key in SOURCE_ROLES}:
        raise SourceBuildError("unknown source role")
    if intelligence_profile not in {
        "balanced.v1",
        "balanced.v2-candidate.1",
        "balanced.v2-candidate.2",
        "balanced.v3",
    }:
        raise SourceBuildError("unknown intelligence profile")
    if source_role == "published-honey" and intelligence_profile != "balanced.v1":
        raise SourceBuildError("published Honey supports only balanced.v1")
    package_role = source_role.replace("-", "_")
    experimental = intelligence_profile != "balanced.v1"
    default_features = (
        '["honey-0-9-1-compat"]'
        if source_role == "published-honey"
        else ('["experimental-profiles"]' if experimental else "[]")
    )
    selected_harness_role = harness_role or "candidate"
    if selected_harness_role not in {
        "published-honey",
        "champion",
        "candidate",
        "harness",
    }:
        raise SourceBuildError("unknown harness source role")
    dependency_lines = []
    for name in PATH_DEPENDENCIES:
        features = (
            ', features = ["experimental-profiles"]'
            if experimental and name in {"cigar-daemon", "cigar-retrieval"}
            else ""
        )
        dependency_lines.append(
            f'{name} = {{ path = "../../sources/{source_role}/crates/{name}"{features} }}'
        )
    lines = [
        "[package]",
        f'name = "cigarbench-source-{package_role}"',
        'version = "0.0.0"',
        'edition = "2024"',
        "publish = false",
        "",
        "[features]",
        f"default = {default_features}",
        "experimental-profiles = []",
        "honey-0-9-1-compat = []",
        "",
        "[[bin]]",
        'name = "cigarbench-source-consumer"',
        f'path = "../../sources/{selected_harness_role}/benches/cigarbench/consumer/src/main.rs"',
        "",
        "[dependencies]",
        *dependency_lines,
        *REGISTRY_DEPENDENCIES,
        "",
        "[workspace]",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _write_new(path: Path, payload: bytes, mode: int) -> None:
    if (
        path.exists()
        or path.is_symlink()
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise SourceBuildError(
            "build output must be create-new in a canonical directory"
        )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_plan(repository_root: Path, plan_path: Path) -> dict[str, Any]:
    if not plan_path.is_absolute() or plan_path.is_symlink():
        raise SourceBuildError("evaluation plan must be an absolute non-symlink file")
    try:
        resolved = plan_path.resolve(strict=True)
    except OSError as error:
        raise SourceBuildError("evaluation plan is unavailable") from error
    if resolved != plan_path or not plan_path.is_file():
        raise SourceBuildError("evaluation plan path is unsafe")
    plan = load_file(plan_path, maximum_bytes=4 * 1024 * 1024)
    SchemaRegistry(repository_root / "schemas/refinement").validate(PLAN_SCHEMA, plan)
    unsigned = dict(plan)
    claimed = unsigned.pop("plan_id")
    if identity(unsigned) != claimed:
        raise SourceBuildError("evaluation plan identity is invalid")
    if not plan["authority"]["execute_tests"] or any(
        plan["authority"][key]
        for key in (
            "edit_product",
            "create_pull_request",
            "merge",
            "release",
            "publish",
            "push_public",
        )
    ):
        raise SourceBuildError("evaluation plan grants unsafe authority")
    return plan


def load_source_consumers(
    *, repository_root: Path, plan_path: Path, build_root: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Path]]:
    """Verify a plan, its build receipt, and all three executable byte identities."""

    root = _canonical_directory(repository_root, "Shadow CIGAR root")
    plan = _load_plan(root, plan_path)
    custody = _canonical_directory(build_root, "source build root")
    receipt_path = custody / "build-set.v1.json"
    if receipt_path.is_symlink() or receipt_path.resolve(strict=True).parent != custody:
        raise SourceBuildError("build receipt escaped its custody root")
    receipt_payload = receipt_path.read_bytes()
    receipt = load_file(receipt_path, maximum_bytes=4 * 1024 * 1024)
    if canonical_bytes(receipt) != receipt_payload:
        raise SourceBuildError("source build receipt is not canonical")
    registry = SchemaRegistry(root / "schemas/refinement")
    registry.validate(BUILD_SCHEMA, receipt)
    unsigned = dict(receipt)
    claimed = unsigned.pop("build_set_id")
    if identity(unsigned) != claimed:
        raise SourceBuildError("source build receipt identity is invalid")
    if (
        receipt["plan_id"] != plan["plan_id"]
        or receipt["profile_id"] != plan["profile_id"]
        or receipt["harness_source"] != plan["harness_source"]
        or receipt["build_profile"] != "release"
    ):
        raise SourceBuildError("source build receipt does not bind its plan")
    profiles = plan.get(
        "intelligence_profiles",
        {"honey": "balanced.v1", "champion": "balanced.v1", "candidate": "balanced.v1"},
    )
    treatments = {
        "published-honey": ("honey", "published_honey"),
        "champion": ("champion", "champion"),
        "candidate": ("candidate", "candidate"),
    }
    rows = {row["source_role"]: row for row in receipt["builds"]}
    if tuple(rows) != tuple(role for role, _key in SOURCE_ROLES):
        raise SourceBuildError("source build receipt inventory is invalid")
    executables: dict[str, Path] = {}
    for role, _plan_key in SOURCE_ROLES:
        treatment, plan_key = treatments[role]
        row = rows[role]
        if (
            row["product_source"] != plan["product_sources"][plan_key]
            or row["harness_source"] != plan["harness_source"]
            or row["intelligence_profile"] != profiles[treatment]
            or not row["source_clean_after_build"]
            or row["status"] != "built"
        ):
            raise SourceBuildError("source build row drifted from its plan")
        relative = Path(row["executable_path"])
        unresolved = custody / relative
        executable = unresolved.resolve(strict=True)
        if (
            relative.is_absolute()
            or unresolved.is_symlink()
            or not executable.is_relative_to(custody)
        ):
            raise SourceBuildError("source consumer escaped build custody")
        metadata = executable.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != row["executable_bytes"]
        ):
            raise SourceBuildError("source consumer metadata drifted")
        sha256 = _sha256(executable)
        if (
            sha256 != row["executable_sha256"]
            or "1220" + sha256 != row["executable_digest"]
        ):
            raise SourceBuildError("source consumer bytes drifted")
        executables[treatment] = executable
    return plan, receipt, executables


def _prepare_root(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise SourceBuildError("build output root must be an absolute non-symlink path")
    parent = path.parent.resolve(strict=True)
    if path.parent != parent or path.exists():
        raise SourceBuildError("build output root must be a canonical create-new path")
    path.mkdir(mode=0o700)
    metadata = path.stat(follow_symlinks=False)
    if stat.S_IMODE(metadata.st_mode) != 0o700 or path.resolve(strict=True) != path:
        raise SourceBuildError("build output root permissions are unsafe")
    for name in ("sources", "adapters", "targets"):
        (path / name).mkdir(mode=0o700)


def _platform() -> tuple[str, str]:
    system = platform.system().lower()
    observed_architecture = platform.machine().lower()
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        observed_architecture, observed_architecture
    )
    if system not in {"darwin", "linux", "windows"} or architecture not in {
        "aarch64",
        "x86_64",
    }:
        raise SourceBuildError("build platform is outside the qualified set")
    return system, architecture


def build_source_consumers(
    *,
    repository_root: Path,
    plan_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build and receipt exact-source consumers for the plan's three profiles."""

    root = _canonical_directory(repository_root, "Shadow CIGAR root")
    plan = _load_plan(root, plan_path)
    _prepare_root(output_root)
    try:
        environment = sanitized_environment(output_root / "build-state")
    except CommandError as error:
        raise SourceBuildError(
            "could not establish a sanitized build environment"
        ) from error
    cargo, cargo_sha256 = _tool("cargo", environment)
    rustc, rustc_sha256 = _tool("rustc", environment)
    git, _git_sha256 = _tool("git", environment)
    cargo_version = _run(
        [cargo, "--version", "--verbose"],
        cwd=root,
        environment=environment,
        timeout=120,
    )
    rustc_version = _run([rustc, "-vV"], cwd=root, environment=environment, timeout=120)

    for source_role, plan_key in SOURCE_ROLES:
        source_root = output_root / "sources" / source_role
        _run(
            [
                git,
                "-C",
                os.fspath(root),
                "worktree",
                "add",
                "--detach",
                os.fspath(source_root),
                plan["product_sources"][plan_key]["revision"],
            ],
            cwd=root,
            environment=environment,
            timeout=300,
        )
        if _git_source(git, source_root) != plan["product_sources"][plan_key]:
            raise SourceBuildError("prepared product worktree identity drifted")

    product_source_roles = {
        canonical_bytes(plan["product_sources"][plan_key]): source_role
        for source_role, plan_key in SOURCE_ROLES
    }
    harness_role = product_source_roles.get(canonical_bytes(plan["harness_source"]))
    if harness_role is None:
        harness_role = "harness"
        harness_root = output_root / "sources" / harness_role
        _run(
            [
                git,
                "-C",
                os.fspath(root),
                "worktree",
                "add",
                "--detach",
                os.fspath(harness_root),
                plan["harness_source"]["revision"],
            ],
            cwd=root,
            environment=environment,
            timeout=300,
        )
        if _git_source(git, harness_root) != plan["harness_source"]:
            raise SourceBuildError("prepared harness worktree identity drifted")

    profiles = plan.get(
        "intelligence_profiles",
        {"honey": "balanced.v1", "champion": "balanced.v1", "candidate": "balanced.v1"},
    )
    treatment_for_role = {
        "published-honey": "honey",
        "champion": "champion",
        "candidate": "candidate",
    }
    builds: list[dict[str, Any]] = []
    for source_role, plan_key in SOURCE_ROLES:
        intelligence_profile = profiles[treatment_for_role[source_role]]
        adapter_root = output_root / "adapters" / source_role
        adapter_root.mkdir(mode=0o700)
        manifest_path = adapter_root / "Cargo.toml"
        manifest = _adapter_manifest(
            source_role,
            intelligence_profile,
            harness_role=harness_role,
        )
        _write_new(manifest_path, manifest, 0o600)
        role_environment = dict(environment)
        role_environment["CARGO_TARGET_DIR"] = os.fspath(
            output_root / "targets" / source_role
        )
        _run(
            [
                cargo,
                "generate-lockfile",
                "--offline",
                "--manifest-path",
                os.fspath(manifest_path),
            ],
            cwd=adapter_root,
            environment=role_environment,
            timeout=1800,
        )
        lock_path = adapter_root / "Cargo.lock"
        _run(
            [
                cargo,
                "build",
                "--release",
                "--locked",
                "--offline",
                "--manifest-path",
                os.fspath(manifest_path),
            ],
            cwd=adapter_root,
            environment=role_environment,
            timeout=7200,
        )
        executable_relative = (
            Path("targets")
            / source_role
            / "release"
            / (
                "cigarbench-source-consumer.exe"
                if platform.system().lower() == "windows"
                else "cigarbench-source-consumer"
            )
        )
        executable = output_root / executable_relative
        executable_sha256 = _sha256(executable)
        source_root = output_root / "sources" / source_role
        status = _run(
            [
                git,
                "-C",
                os.fspath(source_root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=source_root,
            environment=environment,
            timeout=120,
        )
        if status:
            raise SourceBuildError("product source changed during its consumer build")
        builds.append(
            {
                "source_role": source_role,
                "product_source": plan["product_sources"][plan_key],
                "harness_source": plan["harness_source"],
                "intelligence_profile": intelligence_profile,
                "adapter_manifest_digest": multihash_bytes(manifest),
                "cargo_lock_digest": multihash_bytes(lock_path.read_bytes()),
                "executable_digest": "1220" + executable_sha256,
                "executable_sha256": executable_sha256,
                "executable_bytes": executable.stat(follow_symlinks=False).st_size,
                "executable_path": executable_relative.as_posix(),
                "source_clean_after_build": True,
                "status": "built",
            }
        )

    system, architecture = _platform()
    body: dict[str, Any] = {
        "schema_version": "cigar.source-consumer-build-set.v1",
        "plan_id": plan["plan_id"],
        "profile_id": plan["profile_id"],
        "harness_source": plan["harness_source"],
        "build_profile": "release",
        "toolchain": {
            "platform": system,
            "architecture": architecture,
            "cargo_executable_sha256": cargo_sha256,
            "cargo_version_digest": multihash_bytes(cargo_version),
            "rustc_executable_sha256": rustc_sha256,
            "rustc_version_digest": multihash_bytes(rustc_version),
        },
        "builds": builds,
    }
    receipt = {**body, "build_set_id": identity(body)}
    registry = SchemaRegistry(root / "schemas/refinement")
    registry.validate(BUILD_SCHEMA, receipt)
    if tuple(row["source_role"] for row in builds) != tuple(
        role for role, _key in SOURCE_ROLES
    ):
        raise SourceBuildError("build set treatment ordering drifted")
    _write_new(output_root / "build-set.v1.json", canonical_bytes(receipt), 0o400)
    return receipt
