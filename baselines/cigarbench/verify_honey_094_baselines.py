#!/usr/bin/env python3
"""Generate and verify immutable Honey 0.9.2/0.9.3 comparator bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Never, Sequence


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "baselines/cigarbench/honey-0.9.4-three-way.v1.json"
VERIFIER_RELATIVE = "baselines/cigarbench/verify_honey_094_baselines.py"
SCHEMA_RELATIVE = (
    "packaging/honey/schemas/honey-0.9.4-comparator-baselines.v1.schema.json"
)
SCHEMA_PATH = ROOT / SCHEMA_RELATIVE
SCHEMA_VERSION = "cigar.honey-0.9.4-comparator-baselines.v1"
MANIFEST_ID = "cigar.honey.0.9.4.three-way-comparators.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
MAX_FILE_BYTES = 256 * 1024 * 1024

MATERIALIZER_GOLDENS = {
    "claude-prompt": "1220e1a9ed6364db8602b84697811afcc32da40ff5c05458db050f203cc992f7a903",
    "fact-set": "12205bf44fa32b4da1095ce6dd1da8f838bc9e816fae0dda7a6105c6b03bd943b69a",
    "json": "12203b50d3cf1c508a1d8540a2c69c6eeee8426443c1764f96f8042f5cd57fda53fa",
    "markdown": "122023b476a4c2a651cc4c7b08cef869f4c06cb2114ea60a9f89025a5ef832fcea3c",
    "mcp-resource": "122001e42c1735bc9a728423075564aad4adfae1cea032b78bc27d4af046ae99bd1b",
}

TREATMENTS = {
    "honey-0.9.2-balanced-v1": {
        "version": "0.9.2",
        "commit": "35538959bce7497311906e4d370334a87abd362b",
        "tree": "1157c5fb32b7faed65a8db5ae1e44505636b872f",
        "selection_profile_id": "balanced_v1",
        "retrieval_profile_id": "cigar.retrieval-profile.balanced.v1",
        "retrieval_profile_digest": "1220c605f248bd6f9d7c476324630b0839fb4c7423009f47f3f13b8b1a62cfeb72ea",
        "release_contract": "packaging/honey/balanced-0.9.2-release-contract.v1.json",
    },
    "honey-0.9.3-balanced-v3": {
        "version": "0.9.3",
        "commit": "a049fbc8ed81c9adc6b1a066ca053c5befc2578a",
        "tree": "7179f2d0b78c8af314aebc8c86d62a0b6067e6ec",
        "selection_profile_id": "balanced_v3",
        "retrieval_profile_id": "cigar.retrieval-profile.balanced.v2-candidate.2",
        "retrieval_profile_digest": "12200a182e948a6f1db35e59b32a5ea9963807f26796303c65065385b84c33f1316a",
        "release_contract": "packaging/honey/balanced-0.9.3-release-contract.v1.json",
    },
}

COMMON_SOURCE_PATHS = (
    "Cargo.lock",
    "Cargo.toml",
    "benches/honey-092-qualification/qualify.py",
    "benches/honey-efficiency/driver/Cargo.lock",
    "benches/honey-efficiency/driver/Cargo.toml",
    "benches/honey-efficiency/driver/src/main.rs",
    "benches/honey-efficiency/honey_efficiency.py",
    "benches/honey-efficiency/profiles.v1.json",
    "benches/honey-efficiency/qualification-fixtures.v1.json",
    "crates/cigar-compiler/Cargo.toml",
    "crates/cigar-compiler/release.json",
    "crates/cigar-retrieval/Cargo.toml",
    "crates/cigar-retrieval/release.json",
    "crates/cigar-store/Cargo.toml",
    "crates/cigar-store/src/sqlite_v5.rs",
    "packaging/honey/efficiency-qualification-profile.v1.json",
    "packaging/honey/schemas/honey-efficiency-reliability-qualification.v1.schema.json",
    "packaging/product-version.v1.json",
)
SOURCE_DIRECTORIES = (
    "crates/cigar-compiler/src",
    "crates/cigar-compiler/tests",
    "crates/cigar-retrieval/src",
    "crates/cigar-retrieval/tests",
)


class BaselineError(RuntimeError):
    """A content-free comparator-binding validation failure."""


def fail(message: str) -> Never:
    raise BaselineError(message)


def canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BaselineError("comparator binding is not canonical JSON") from error


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def regular_file(path: Path, label: str) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as error:
        raise BaselineError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_size <= 0
        or status.st_size > MAX_FILE_BYTES
    ):
        fail(f"{label} is not one bounded regular file")
    return status


def digest_file(path: Path, label: str) -> str:
    regular_file(path, label)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(path: Path, label: str) -> dict[str, Any]:
    regular_file(path, label)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                fail(f"{label} contains a duplicate key")
            output[key] = value
        return output

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} root is not an object")
    return value


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} has missing or unexpected fields")
    return value


def sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not a SHA-256 digest")
    return value


def git_object(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_OBJECT.fullmatch(value) is None:
        fail(f"{label} is not an immutable Git object ID")
    return value


def safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} is not a safe relative path")
    return value


def run(command: list[str], cwd: Path, label: str) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BaselineError(f"{label} could not execute") from error
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        fail(f"{label} failed")
    return result.stdout.strip()


def git(root: Path, *arguments: str) -> str:
    return run(["git", *arguments], root, "Git source-binding command")


def source_paths(root: Path, configuration: dict[str, str]) -> list[str]:
    paths = set(COMMON_SOURCE_PATHS)
    paths.add(configuration["release_contract"])
    for relative in SOURCE_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir() or directory.is_symlink():
            fail("comparator source directory is unavailable")
        paths.update(
            path.relative_to(root).as_posix()
            for path in directory.rglob("*.rs")
            if path.is_file() and not path.is_symlink()
        )
    return sorted(paths)


def file_records(root: Path, paths: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative in paths:
        safe_relative(relative, "source binding path")
        path = root / relative
        status = regular_file(path, "bound source file")
        records.append(
            {
                "bytes": status.st_size,
                "path": relative,
                "sha256": digest_file(path, "bound source file"),
            }
        )
    return records


def require_golden_authority(root: Path, configuration: dict[str, str]) -> None:
    retrieval = (root / "crates/cigar-retrieval/src/profile.rs").read_text(
        encoding="utf-8"
    )
    required = (
        configuration["retrieval_profile_id"],
        configuration["retrieval_profile_digest"],
    )
    if any(value not in retrieval for value in required):
        fail("retrieval profile golden does not match its source authority")
    compiler = (
        root / "crates/cigar-compiler/tests/materialization_delta_cache.rs"
    ).read_text(encoding="utf-8")
    if any(value not in compiler for value in MATERIALIZER_GOLDENS.values()):
        fail("compiler materialization golden inventory is incomplete")


def source_binding(
    root: Path, treatment_id: str, configuration: dict[str, str]
) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        fail("comparator source root is unavailable")
    commit = git(resolved, "rev-parse", "--verify", "HEAD^{commit}")
    tree = git(resolved, "rev-parse", "--verify", "HEAD^{tree}")
    status = git(resolved, "status", "--porcelain=v1", "--untracked-files=all")
    if commit != configuration["commit"] or tree != configuration["tree"]:
        fail("comparator source does not match the frozen commit and tree")
    if status:
        fail("comparator source worktree is dirty")
    version = strict_json(
        resolved / "packaging/product-version.v1.json", "product version authority"
    )
    if version.get("version") != configuration["version"]:
        fail("comparator version and treatment disagree")
    require_golden_authority(resolved, configuration)
    records = file_records(resolved, source_paths(resolved, configuration))
    by_path = {record["path"]: record for record in records}
    cargo_lock = by_path["Cargo.lock"]
    profile_path = "packaging/honey/efficiency-qualification-profile.v1.json"
    retrieval_path = "crates/cigar-retrieval/src/profile.rs"
    compiler_golden_path = "crates/cigar-compiler/tests/materialization_delta_cache.rs"
    return {
        "commit": commit,
        "tree": tree,
        "revision_kind": "commit",
        "worktree_dirty": False,
        "worktree_status": [],
        "source_file_count": len(records),
        "source_files": records,
        "source_set_sha256": digest_bytes(canonical(records)),
        "cargo_lock": {
            "bytes": cargo_lock["bytes"],
            "path": "Cargo.lock",
            "sha256": cargo_lock["sha256"],
        },
        "profile": {
            "selection_profile_id": configuration["selection_profile_id"],
            "retrieval_profile_id": configuration["retrieval_profile_id"],
            "retrieval_profile_digest": configuration["retrieval_profile_digest"],
            "retrieval_authority_path": retrieval_path,
            "retrieval_authority_sha256": by_path[retrieval_path]["sha256"],
            "release_profile_path": profile_path,
            "release_profile_sha256": by_path[profile_path]["sha256"],
        },
        "goldens": {
            "compiler_authority_path": compiler_golden_path,
            "compiler_authority_sha256": by_path[compiler_golden_path]["sha256"],
            "materializer_digests": dict(sorted(MATERIALIZER_GOLDENS.items())),
        },
        "treatment_id": treatment_id,
        "version": configuration["version"],
    }


def installed_binding(
    root: Path, configuration: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = root.resolve(strict=True)
    artifacts: dict[str, Any] = {}
    installed: dict[str, Any] = {}
    for binary_id in ("cigar", "cigard"):
        path = resolved / "bin" / binary_id
        status = regular_file(path, "installed comparator binary")
        if stat.S_IMODE(status.st_mode) != 0o755:
            fail("installed comparator binary mode is not 0755")
        digest = digest_file(path, "installed comparator binary")
        try:
            identity = json.loads(
                run([str(path), "--version"], resolved, "binary identity")
            )
        except json.JSONDecodeError as error:
            raise BaselineError("installed binary identity is invalid JSON") from error
        if (
            not isinstance(identity, dict)
            or identity.get("version") != configuration["version"]
            or identity.get("source_revision") != configuration["commit"]
            or identity.get("context_abi") != "cigar.context.v1"
            or identity.get("build_profile") != "release"
        ):
            fail("installed binary identity does not match its source binding")
        artifact_id = f"{binary_id}-macos-aarch64-release"
        artifacts[binary_id] = {
            "artifact_id": artifact_id,
            "bytes": status.st_size,
            "mode": "0755",
            "sha256": digest,
        }
        installed[binary_id] = {
            "artifact_id": artifact_id,
            "binary_id": binary_id,
            "bytes": status.st_size,
            "identity": identity,
            "sha256": digest,
        }
    return artifacts, installed


def installed_runner_binding(
    installed_root: Path,
    source_root: Path,
    configuration: dict[str, str],
    expected_sha256: str,
) -> dict[str, Any]:
    resolved_install = installed_root.resolve(strict=True)
    resolved_source = source_root.resolve(strict=True)
    path = resolved_install / "bin/hiero-cigar-bench-runner"
    status = regular_file(path, "installed Hiero comparator runner")
    if stat.S_IMODE(status.st_mode) != 0o755:
        fail("installed Hiero comparator runner mode is not 0755")
    digest = digest_file(path, "installed Hiero comparator runner")
    if digest != expected_sha256:
        fail("installed Hiero runner differs from the executed evidence binary")
    sandbox = Path("/usr/bin/sandbox-exec")
    regular_file(sandbox, "macOS sandbox executor")
    profile = (
        f'(version 1)(allow default)(deny file-read* (subpath "{resolved_source}"))'
    )
    output = run(
        [
            str(sandbox),
            "-p",
            profile,
            str(path),
            "--workflow",
            "solo",
            "--trials",
            "1",
            "--warmups",
            "0",
            "--library-label",
            f"installed-{configuration['version']}",
            "--product-version",
            configuration["version"],
            "--source-revision",
            configuration["commit"],
        ],
        resolved_install,
        "sandboxed installed Hiero runner",
    )
    try:
        observation = json.loads(output)
    except json.JSONDecodeError as error:
        raise BaselineError("installed Hiero runner output is invalid JSON") from error
    if (
        not isinstance(observation, dict)
        or observation.get("workflow") != "solo"
        or observation.get("measured_runs") != 1
        or len(observation.get("observations", [])) != 1
    ):
        fail("installed Hiero runner did not complete the sandboxed source-denial test")
    return {
        "binary_id": "hiero-cigar-bench-runner",
        "bytes": status.st_size,
        "mode": "0755",
        "sha256": digest,
        "source_access_test": "pass-with-bound-source-root-denied",
    }


def validate_hiero(
    evidence: dict[str, Any], sources: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if evidence.get("schema_version") != "hiero.cigar-version-comparison.v1":
        fail("Hiero evidence schema is invalid")
    cohort = evidence.get("cohort")
    if (
        not isinstance(cohort, dict)
        or cohort.get("workflow_count") != 5
        or cohort.get("trials_per_workflow") != 20
        or cohort.get("warmups_per_workflow") != 5
        or cohort.get("executions_per_library") != 100
        or cohort.get("total_measured_executions") != 200
        or cohort.get("paired_inputs") is not True
    ):
        fail("Hiero comparator cohort is not the frozen five-by-20 design")
    bindings = evidence.get("sources")
    runners = evidence.get("runner")
    if not isinstance(bindings, dict) or not isinstance(runners, dict):
        fail("Hiero evidence bindings are missing")
    role_by_treatment = {
        "honey-0.9.2-balanced-v1": "stable",
        "honey-0.9.3-balanced-v3": "candidate",
    }
    output: dict[str, Any] = {}
    for treatment_id, role in role_by_treatment.items():
        source = sources[treatment_id]
        observed = bindings.get(role)
        runner = runners.get(role)
        if (
            not isinstance(observed, dict)
            or not isinstance(runner, dict)
            or observed.get("commit") != source["commit"]
            or observed.get("tree") != source["tree"]
            or observed.get("worktree_dirty") is not False
            or observed.get("product_version") != source["version"]
        ):
            fail("Hiero evidence does not bind the frozen comparator source")
        output[treatment_id] = {
            "hiero_source_set_sha256": sha(
                observed.get("source_set_sha256"), "Hiero source-set digest"
            ),
            "runner_binary_sha256": sha(
                runner.get("binary_sha256"), "Hiero runner digest"
            ),
        }
    output["shared"] = {
        "manifest_template_sha256": sha(
            runners.get("manifest_template_sha256"), "Hiero manifest-template digest"
        ),
        "orchestrator_sha256": sha(
            runners.get("orchestrator_sha256"), "Hiero orchestrator digest"
        ),
        "runner_source_sha256": sha(
            runners.get("source_sha256"), "Hiero runner-source digest"
        ),
    }
    return output


def build_manifest(arguments: argparse.Namespace) -> dict[str, Any]:
    roots = {
        "honey-0.9.2-balanced-v1": arguments.source_092,
        "honey-0.9.3-balanced-v3": arguments.source_093,
    }
    installed_roots = {
        "honey-0.9.2-balanced-v1": arguments.installed_092,
        "honey-0.9.3-balanced-v3": arguments.installed_093,
    }
    sources = {
        treatment_id: source_binding(
            Path(roots[treatment_id]), treatment_id, configuration
        )
        for treatment_id, configuration in TREATMENTS.items()
    }
    hiero_path = Path(arguments.hiero_json).resolve(strict=True)
    report_path = Path(arguments.hiero_report).resolve(strict=True)
    hiero_document = strict_json(hiero_path, "Hiero raw evidence")
    hiero = validate_hiero(hiero_document, sources)
    treatments: dict[str, Any] = {}
    for treatment_id, configuration in TREATMENTS.items():
        artifacts, installed = installed_binding(
            Path(installed_roots[treatment_id]), configuration
        )
        source = sources[treatment_id]
        hiero_execution = dict(hiero[treatment_id])
        hiero_execution["installed_runner"] = installed_runner_binding(
            Path(installed_roots[treatment_id]),
            Path(roots[treatment_id]),
            configuration,
            hiero_execution["runner_binary_sha256"],
        )
        treatments[treatment_id] = {
            "treatment_id": treatment_id,
            "version": configuration["version"],
            "source": source,
            "artifacts": artifacts,
            "artifact_set_sha256": digest_bytes(canonical(artifacts)),
            "installed_binaries": installed,
            "installed_binary_set_sha256": digest_bytes(canonical(installed)),
            "hiero_execution": hiero_execution,
            "qualification_status": "pass",
        }
    schema_digest = digest_file(SCHEMA_PATH, "comparator baseline schema")
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": MANIFEST_ID,
        "schema_binding": {
            "path": SCHEMA_RELATIVE,
            "sha256": schema_digest,
        },
        "verifier_binding": {
            "path": VERIFIER_RELATIVE,
            "sha256": digest_file(ROOT / VERIFIER_RELATIVE, "comparator verifier"),
        },
        "candidate_policy": {
            "candidate_version": "0.9.4",
            "candidate_source_state": "unbound-until-candidate-freeze",
            "forbid_comparator_source_reuse": True,
            "forbidden_commits": sorted(
                value["commit"] for value in TREATMENTS.values()
            ),
            "forbidden_trees": sorted(value["tree"] for value in TREATMENTS.values()),
        },
        "harness_binding": {
            **hiero["shared"],
            "raw_evidence": {
                "artifact_name": hiero_path.name,
                "bytes": regular_file(hiero_path, "Hiero raw evidence").st_size,
                "sha256": digest_file(hiero_path, "Hiero raw evidence"),
            },
            "report": {
                "artifact_name": report_path.name,
                "bytes": regular_file(report_path, "Hiero report").st_size,
                "sha256": digest_file(report_path, "Hiero report"),
            },
            "workflow_count": 5,
            "trials_per_workflow": 20,
            "warmups_per_workflow": 5,
        },
        "treatments": treatments,
    }


def validate_digest_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(value, {"artifact_id", "bytes", "mode", "sha256"}, label)
    if not isinstance(record["artifact_id"], str) or not record["artifact_id"]:
        fail(f"{label} artifact ID is invalid")
    if (
        not isinstance(record["bytes"], int)
        or isinstance(record["bytes"], bool)
        or record["bytes"] <= 0
    ):
        fail(f"{label} byte count is invalid")
    if record["mode"] != "0755":
        fail(f"{label} mode is invalid")
    sha(record["sha256"], f"{label} digest")
    return record


def validate_manifest(
    document: dict[str, Any],
    *,
    repository_root: Path | None = ROOT,
    candidate_source: dict[str, str] | None = None,
) -> None:
    exact_keys(
        document,
        {
            "candidate_policy",
            "harness_binding",
            "manifest_id",
            "schema_binding",
            "schema_version",
            "treatments",
            "verifier_binding",
        },
        "comparator manifest",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or document["manifest_id"] != MANIFEST_ID
    ):
        fail("comparator manifest identity is invalid")
    schema_binding = exact_keys(
        document["schema_binding"], {"path", "sha256"}, "schema binding"
    )
    if schema_binding["path"] != SCHEMA_RELATIVE:
        fail("comparator schema path is invalid")
    sha(schema_binding["sha256"], "comparator schema digest")
    if repository_root is not None:
        if (
            digest_file(repository_root / SCHEMA_RELATIVE, "comparator schema")
            != schema_binding["sha256"]
        ):
            fail("comparator schema digest drifted")
    verifier_binding = exact_keys(
        document["verifier_binding"], {"path", "sha256"}, "verifier binding"
    )
    if verifier_binding["path"] != VERIFIER_RELATIVE:
        fail("comparator verifier path is invalid")
    sha(verifier_binding["sha256"], "comparator verifier digest")
    if repository_root is not None and (
        digest_file(repository_root / VERIFIER_RELATIVE, "comparator verifier")
        != verifier_binding["sha256"]
    ):
        fail("comparator verifier digest drifted")
    treatments = document["treatments"]
    if not isinstance(treatments, dict) or set(treatments) != set(TREATMENTS):
        fail("comparator treatment inventory is not exact")
    treatment_ids: list[str] = []
    commits: list[str] = []
    trees: list[str] = []
    source_sets: list[str] = []
    for treatment_id, configuration in TREATMENTS.items():
        treatment = exact_keys(
            treatments[treatment_id],
            {
                "artifact_set_sha256",
                "artifacts",
                "hiero_execution",
                "installed_binaries",
                "installed_binary_set_sha256",
                "qualification_status",
                "source",
                "treatment_id",
                "version",
            },
            "comparator treatment",
        )
        if (
            treatment["treatment_id"] != treatment_id
            or treatment["version"] != configuration["version"]
            or treatment["qualification_status"] != "pass"
        ):
            fail("comparator treatment identity or status is invalid")
        treatment_ids.append(treatment["treatment_id"])
        source = treatment["source"]
        required_source = {
            "cargo_lock",
            "commit",
            "goldens",
            "profile",
            "revision_kind",
            "source_file_count",
            "source_files",
            "source_set_sha256",
            "treatment_id",
            "tree",
            "version",
            "worktree_dirty",
            "worktree_status",
        }
        exact_keys(source, required_source, "comparator source binding")
        commit = git_object(source["commit"], "comparator commit")
        tree = git_object(source["tree"], "comparator tree")
        if (
            commit != configuration["commit"]
            or tree != configuration["tree"]
            or source["revision_kind"] != "commit"
            or source["worktree_dirty"] is not False
            or source["worktree_status"] != []
            or source["treatment_id"] != treatment_id
            or source["version"] != configuration["version"]
        ):
            fail("comparator source is dirty, moving, or mismatched")
        commits.append(commit)
        trees.append(tree)
        source_sets.append(sha(source["source_set_sha256"], "source-set digest"))
        files = source["source_files"]
        if (
            not isinstance(files, list)
            or not files
            or source["source_file_count"] != len(files)
        ):
            fail("comparator source-file inventory is incomplete")
        observed_paths: list[str] = []
        for record in files:
            exact_keys(record, {"bytes", "path", "sha256"}, "source-file binding")
            observed_paths.append(safe_relative(record["path"], "source-file path"))
            if (
                not isinstance(record["bytes"], int)
                or isinstance(record["bytes"], bool)
                or record["bytes"] <= 0
            ):
                fail("source-file byte count is invalid")
            sha(record["sha256"], "source-file digest")
        if len(set(observed_paths)) != len(observed_paths) or observed_paths != sorted(
            observed_paths
        ):
            fail("source-file paths are duplicate or noncanonical")
        if digest_bytes(canonical(files)) != source["source_set_sha256"]:
            fail("source-set digest is invalid")
        cargo = exact_keys(
            source["cargo_lock"], {"bytes", "path", "sha256"}, "Cargo.lock binding"
        )
        if cargo["path"] != "Cargo.lock":
            fail("Cargo.lock binding path is invalid")
        cargo_record = next(
            (record for record in files if record["path"] == "Cargo.lock"), None
        )
        if cargo_record != cargo:
            fail("Cargo.lock binding is absent or inconsistent")
        profile = exact_keys(
            source["profile"],
            {
                "release_profile_path",
                "release_profile_sha256",
                "retrieval_authority_path",
                "retrieval_authority_sha256",
                "retrieval_profile_digest",
                "retrieval_profile_id",
                "selection_profile_id",
            },
            "profile binding",
        )
        if (
            profile["selection_profile_id"] != configuration["selection_profile_id"]
            or profile["retrieval_profile_id"] != configuration["retrieval_profile_id"]
            or profile["retrieval_profile_digest"]
            != configuration["retrieval_profile_digest"]
        ):
            fail("comparator profile mismatches its treatment")
        for field in ("release_profile_sha256", "retrieval_authority_sha256"):
            sha(profile[field], "profile authority digest")
        goldens = exact_keys(
            source["goldens"],
            {
                "compiler_authority_path",
                "compiler_authority_sha256",
                "materializer_digests",
            },
            "golden binding",
        )
        sha(goldens["compiler_authority_sha256"], "compiler golden authority digest")
        if goldens["materializer_digests"] != dict(
            sorted(MATERIALIZER_GOLDENS.items())
        ):
            fail("compiler golden digest inventory is invalid")
        artifacts = treatment["artifacts"]
        installed = treatment["installed_binaries"]
        if not isinstance(artifacts, dict) or set(artifacts) != {"cigar", "cigard"}:
            fail("comparator artifact inventory is incomplete")
        if not isinstance(installed, dict) or set(installed) != {"cigar", "cigard"}:
            fail("installed binary digest inventory is incomplete")
        for binary_id in ("cigar", "cigard"):
            artifact = validate_digest_record(
                artifacts[binary_id], "comparator artifact"
            )
            binary = exact_keys(
                installed[binary_id],
                {"artifact_id", "binary_id", "bytes", "identity", "sha256"},
                "installed binary binding",
            )
            if (
                binary["binary_id"] != binary_id
                or binary["artifact_id"] != artifact["artifact_id"]
                or binary["bytes"] != artifact["bytes"]
                or binary["sha256"] != artifact["sha256"]
                or binary.get("identity", {}).get("version") != configuration["version"]
                or binary.get("identity", {}).get("source_revision") != commit
            ):
                fail("installed binary does not match its build artifact or source")
            sha(binary["sha256"], "installed binary digest")
        if digest_bytes(canonical(artifacts)) != treatment["artifact_set_sha256"]:
            fail("artifact-set digest is invalid")
        if (
            digest_bytes(canonical(installed))
            != treatment["installed_binary_set_sha256"]
        ):
            fail("installed-binary-set digest is invalid")
        hiero = exact_keys(
            treatment["hiero_execution"],
            {"hiero_source_set_sha256", "installed_runner", "runner_binary_sha256"},
            "Hiero execution binding",
        )
        sha(hiero["hiero_source_set_sha256"], "Hiero source-set digest")
        runner_digest = sha(
            hiero["runner_binary_sha256"], "executed Hiero runner digest"
        )
        installed_runner = exact_keys(
            hiero["installed_runner"],
            {"binary_id", "bytes", "mode", "sha256", "source_access_test"},
            "installed Hiero runner binding",
        )
        if (
            installed_runner["binary_id"] != "hiero-cigar-bench-runner"
            or installed_runner["mode"] != "0755"
            or installed_runner["source_access_test"]
            != "pass-with-bound-source-root-denied"
            or installed_runner["sha256"] != runner_digest
            or not isinstance(installed_runner["bytes"], int)
            or isinstance(installed_runner["bytes"], bool)
            or installed_runner["bytes"] <= 0
        ):
            fail("installed Hiero runner is not the source-denied executed artifact")
    if (
        len(set(treatment_ids)) != len(treatment_ids)
        or len(set(commits)) != len(commits)
        or len(set(trees)) != len(trees)
        or len(set(source_sets)) != len(source_sets)
    ):
        fail("comparator treatment or source identities are duplicated")
    policy = exact_keys(
        document["candidate_policy"],
        {
            "candidate_source_state",
            "candidate_version",
            "forbid_comparator_source_reuse",
            "forbidden_commits",
            "forbidden_trees",
        },
        "candidate source policy",
    )
    if (
        policy["candidate_version"] != "0.9.4"
        or policy["candidate_source_state"] != "unbound-until-candidate-freeze"
        or policy["forbid_comparator_source_reuse"] is not True
        or policy["forbidden_commits"] != sorted(commits)
        or policy["forbidden_trees"] != sorted(trees)
    ):
        fail("candidate source-reuse policy is invalid")
    if candidate_source is not None and (
        candidate_source.get("commit") in commits
        or candidate_source.get("tree") in trees
    ):
        fail("candidate source reuses a frozen comparator commit or tree")
    harness = document["harness_binding"]
    required_harness = {
        "manifest_template_sha256",
        "orchestrator_sha256",
        "raw_evidence",
        "report",
        "runner_source_sha256",
        "trials_per_workflow",
        "warmups_per_workflow",
        "workflow_count",
    }
    exact_keys(harness, required_harness, "Hiero harness binding")
    if (
        harness["workflow_count"] != 5
        or harness["trials_per_workflow"] != 20
        or harness["warmups_per_workflow"] != 5
    ):
        fail("Hiero harness cohort binding is invalid")
    for field in (
        "manifest_template_sha256",
        "orchestrator_sha256",
        "runner_source_sha256",
    ):
        sha(harness[field], "Hiero harness digest")
    for name in ("raw_evidence", "report"):
        record = exact_keys(
            harness[name],
            {"artifact_name", "bytes", "sha256"},
            "Hiero evidence artifact",
        )
        if not isinstance(record["artifact_name"], str) or not record["artifact_name"]:
            fail("Hiero evidence artifact name is invalid")
        if (
            not isinstance(record["bytes"], int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] <= 0
        ):
            fail("Hiero evidence artifact byte count is invalid")
        sha(record["sha256"], "Hiero evidence artifact digest")


def write_manifest(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def add_inputs(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--source-092", type=Path, required=required)
    parser.add_argument("--source-093", type=Path, required=required)
    parser.add_argument("--installed-092", type=Path, required=required)
    parser.add_argument("--installed-093", type=Path, required=required)
    parser.add_argument("--hiero-json", type=Path, required=required)
    parser.add_argument("--hiero-report", type=Path, required=required)


def parser() -> argparse.ArgumentParser:
    output = argparse.ArgumentParser(description=__doc__)
    commands = output.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    add_inputs(generate, required=True)
    generate.add_argument("--output", type=Path, default=MANIFEST_PATH)
    check = commands.add_parser("check")
    add_inputs(check, required=False)
    check.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    check.add_argument("--candidate-root", type=Path)
    return output


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "generate":
        document = build_manifest(arguments)
        validate_manifest(document)
        write_manifest(arguments.output, document)
        print(f"generated immutable comparator manifest {MANIFEST_ID}")
        return 0
    document = strict_json(arguments.manifest, "comparator manifest")
    candidate_source = None
    if arguments.candidate_root is not None:
        root = arguments.candidate_root.resolve(strict=True)
        candidate_source = {
            "commit": git(root, "rev-parse", "--verify", "HEAD^{commit}"),
            "tree": git(root, "rev-parse", "--verify", "HEAD^{tree}"),
        }
    validate_manifest(document, candidate_source=candidate_source)
    provided = (
        arguments.source_092,
        arguments.source_093,
        arguments.installed_092,
        arguments.installed_093,
        arguments.hiero_json,
        arguments.hiero_report,
    )
    if any(value is not None for value in provided):
        if any(value is None for value in provided):
            fail(
                "exact comparator reproduction requires every source, install, and Hiero input"
            )
        expected = build_manifest(arguments)
        if document != expected:
            fail(
                "comparator manifest does not reproduce from supplied immutable inputs"
            )
    print(f"validated immutable comparator manifest {MANIFEST_ID}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineError, OSError, ValueError) as error:
        raise SystemExit(f"Honey 0.9.4 comparator baseline failed: {error}") from error
