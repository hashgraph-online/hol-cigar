"""Exact Git worktree isolation, snapshots, and diff-policy enforcement."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, identity, safe_relative_path, secure_read

TRIAL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40,64}$")
MAXIMUM_GIT_OUTPUT = 64 * 1024 * 1024
MAXIMUM_CHANGED_PATHS = 10_000
MAXIMUM_SNAPSHOT_BYTES = 64 * 1024 * 1024


class WorkspaceError(RuntimeError):
    """A source/worktree identity, path, or diff invariant was violated."""


def _git(
    repository: Path,
    *arguments: str,
    allow_failure: bool = False,
) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkspaceError("Git command could not be executed") from error
    if (
        len(result.stdout) > MAXIMUM_GIT_OUTPUT
        or len(result.stderr) > MAXIMUM_GIT_OUTPUT
    ):
        raise WorkspaceError("Git command output exceeded its bound")
    if result.returncode != 0 and not allow_failure:
        raise WorkspaceError("Git command failed")
    return result.stdout if result.returncode == 0 else b""


def repository_identity(repository: Path, *, require_clean: bool) -> dict[str, Any]:
    if not repository.is_absolute() or repository.is_symlink():
        raise WorkspaceError("repository must be an absolute real path")
    resolved = repository.resolve(strict=True)
    if repository != resolved:
        raise WorkspaceError("repository path must not contain aliases or symlinks")
    top = Path(_git(resolved, "rev-parse", "--show-toplevel").decode().strip())
    if top.resolve(strict=True) != resolved:
        raise WorkspaceError("repository path is not the Git worktree root")
    revision = _git(resolved, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = _git(resolved, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    branch = (
        _git(resolved, "symbolic-ref", "--short", "HEAD", allow_failure=True)
        .decode()
        .strip()
    )
    status = _git(
        resolved,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--no-renames",
    )
    if (
        GIT_OBJECT.fullmatch(revision) is None
        or GIT_OBJECT.fullmatch(tree) is None
        or not branch
    ):
        raise WorkspaceError("repository source identity is malformed or detached")
    if require_clean and status:
        raise WorkspaceError("repository must be clean")
    common = Path(_git(resolved, "rev-parse", "--git-common-dir").decode().strip())
    if not common.is_absolute():
        common = resolved / common
    return {
        "revision": revision,
        "tree": tree,
        "branch": branch,
        "clean": not status,
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "common_dir": str(common.resolve(strict=True)),
    }


def resolve_commit(repository: Path, reference: str) -> str:
    if (
        not isinstance(reference, str)
        or REFERENCE.fullmatch(reference) is None
        or ".." in reference
        or "//" in reference
        or "@{" in reference
        or reference.endswith(("/", ".", ".lock"))
        or "/." in reference
    ):
        raise WorkspaceError("champion reference is invalid")
    revision = (
        _git(
            repository,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{reference}^{{commit}}",
        )
        .decode()
        .strip()
    )
    if GIT_OBJECT.fullmatch(revision) is None:
        raise WorkspaceError("champion reference did not resolve to a commit")
    return revision


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _real_absolute_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise WorkspaceError(f"{label} must be an absolute real directory")
    resolved = path.resolve(strict=True)
    if path != resolved or not resolved.is_dir():
        raise WorkspaceError(f"{label} must not contain aliases or symlinks")
    return resolved


def validate_worktree_record(
    record: dict[str, Any],
    *,
    champion_repository: Path | None = None,
) -> dict[str, Any]:
    """Validate every persisted worktree field before using it as authority."""
    required = {
        "trial_id",
        "branch",
        "worktree_path",
        "champion_revision",
        "champion_tree",
        "git_common_dir",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise WorkspaceError("worktree record is malformed")
    if any(not isinstance(record[field], str) for field in required):
        raise WorkspaceError("worktree record values must be strings")
    trial_id = record["trial_id"]
    if TRIAL_ID.fullmatch(trial_id) is None:
        raise WorkspaceError("worktree trial ID is malformed")
    if record["branch"] != f"refine/trial-{trial_id}":
        raise WorkspaceError("worktree branch is not exact")
    for field in ("champion_revision", "champion_tree"):
        if GIT_OBJECT.fullmatch(record[field]) is None:
            raise WorkspaceError("worktree Git object is malformed")

    common = _real_absolute_directory(
        Path(record["git_common_dir"]), "Git common directory"
    )
    destination = Path(record["worktree_path"])
    if not destination.is_absolute() or destination.is_symlink():
        raise WorkspaceError("recorded worktree path is unsafe")
    parent = _real_absolute_directory(destination.parent, "worktree parent")
    exact_destination = parent / trial_id
    if destination != exact_destination:
        raise WorkspaceError("recorded worktree path is not exact")
    if destination.exists() and destination.resolve(strict=True) != destination:
        raise WorkspaceError("recorded worktree contains aliases or symlinks")

    if champion_repository is not None:
        champion = _real_absolute_directory(champion_repository, "champion repository")
        champion_identity = repository_identity(champion, require_clean=True)
        if champion_identity["common_dir"] != str(common):
            raise WorkspaceError("worktree record belongs to another repository")
        if _is_within(destination, champion) or _is_within(champion, destination):
            raise WorkspaceError("worktree path aliases or contains the champion")
    return dict(record)


def create_worktree(
    champion_repository: Path,
    worktree_root: Path,
    *,
    trial_id: str,
    champion_ref: str,
) -> dict[str, Any]:
    intent = plan_worktree(
        champion_repository,
        worktree_root,
        trial_id=trial_id,
        champion_ref=champion_ref,
    )
    return materialize_worktree(champion_repository, intent)


def plan_worktree(
    champion_repository: Path,
    worktree_root: Path,
    *,
    trial_id: str,
    champion_ref: str,
) -> dict[str, Any]:
    if TRIAL_ID.fullmatch(trial_id) is None:
        raise WorkspaceError("trial ID is invalid")
    champion = _real_absolute_directory(champion_repository, "champion repository")
    champion_identity = repository_identity(champion, require_clean=True)
    root = _real_absolute_directory(worktree_root, "worktree root")
    if _is_within(root, champion) or _is_within(champion, root):
        raise WorkspaceError("worktree root aliases or contains the champion")
    destination = root / trial_id
    if destination.exists() or destination.is_symlink():
        raise WorkspaceError("trial worktree path already exists")
    revision = resolve_commit(champion, champion_ref)
    tree = (
        _git(champion, "rev-parse", "--verify", f"{revision}^{{tree}}").decode().strip()
    )
    branch = f"refine/trial-{trial_id}"
    if _git(
        champion,
        "show-ref",
        "--verify",
        f"refs/heads/{branch}",
        allow_failure=True,
    ):
        raise WorkspaceError("trial branch already exists")
    intent = {
        "trial_id": trial_id,
        "branch": branch,
        "worktree_path": str(destination),
        "champion_revision": revision,
        "champion_tree": tree,
        "git_common_dir": champion_identity["common_dir"],
    }
    return validate_worktree_record(intent, champion_repository=champion)


def materialize_worktree(
    champion_repository: Path,
    intent: dict[str, Any],
) -> dict[str, Any]:
    champion = _real_absolute_directory(champion_repository, "champion repository")
    before = repository_identity(champion, require_clean=True)
    intent = validate_worktree_record(intent, champion_repository=champion)
    destination = Path(intent["worktree_path"])
    if destination.exists() or destination.is_symlink():
        raise WorkspaceError("trial worktree path already exists")
    if before["common_dir"] != intent["git_common_dir"]:
        raise WorkspaceError("worktree intent belongs to another repository")
    _git(
        champion,
        "worktree",
        "add",
        "-b",
        intent["branch"],
        str(destination),
        intent["champion_revision"],
    )
    try:
        isolated = repository_identity(destination, require_clean=True)
        if (
            isolated["revision"] != intent["champion_revision"]
            or isolated["tree"] != intent["champion_tree"]
            or isolated["branch"] != intent["branch"]
            or isolated["common_dir"] != before["common_dir"]
        ):
            raise WorkspaceError("created worktree identity is not exact")
        after = repository_identity(champion, require_clean=True)
        if after != before:
            raise WorkspaceError("champion changed while the worktree was created")
        return dict(intent)
    except BaseException:
        _git(champion, "worktree", "remove", str(destination), allow_failure=True)
        raise


def inspect_worktree(
    champion_repository: Path, record: dict[str, Any]
) -> dict[str, Any]:
    champion_path = _real_absolute_directory(champion_repository, "champion repository")
    record = validate_worktree_record(record, champion_repository=champion_path)
    champion = repository_identity(champion_path, require_clean=True)
    path = Path(record["worktree_path"])
    if not path.exists():
        return {"status": "missing", "resumable": False, "reason": "worktree_missing"}
    isolated = repository_identity(path, require_clean=False)
    exact = (
        isolated["branch"] == record["branch"]
        and isolated["revision"] == record["champion_revision"]
        and isolated["tree"] == record["champion_tree"]
        and isolated["common_dir"] == record["git_common_dir"]
        and champion["common_dir"] == record["git_common_dir"]
    )
    if not exact:
        return {"status": "invalid", "resumable": False, "reason": "identity_mismatch"}
    return {
        "status": "present",
        "resumable": True,
        "reason": None,
        "clean": isolated["clean"],
        "revision": isolated["revision"],
        "tree": isolated["tree"],
        "branch": isolated["branch"],
    }


def cleanup_preview(
    champion_repository: Path, record: dict[str, Any]
) -> dict[str, Any]:
    inspection = inspect_worktree(champion_repository, record)
    return {
        "trial_id": record["trial_id"],
        "worktree_path": record["worktree_path"],
        "branch": record["branch"],
        "inspection": inspection,
        "actions": (
            ["git-worktree-remove", "retain-branch"]
            if inspection["status"] == "present" and inspection.get("clean")
            else []
        ),
        "executable": inspection["status"] == "present"
        and inspection.get("clean") is True,
    }


def clean_worktree(champion_repository: Path, record: dict[str, Any]) -> dict[str, Any]:
    preview = cleanup_preview(champion_repository, record)
    if not preview["executable"]:
        raise WorkspaceError("worktree cleanup is not safe to execute")
    champion_path = _real_absolute_directory(champion_repository, "champion repository")
    champion_before = repository_identity(champion_path, require_clean=True)
    _git(champion_path, "worktree", "remove", record["worktree_path"])
    champion_after = repository_identity(champion_path, require_clean=True)
    if champion_after != champion_before:
        raise WorkspaceError("champion changed during worktree cleanup")
    if Path(record["worktree_path"]).exists():
        raise WorkspaceError("worktree path remains after cleanup")
    retained = retained_branch_revision(champion_path, record)
    return {
        "trial_id": record["trial_id"],
        "status": "cleaned",
        "branch_retained": record["branch"],
        "branch_revision": retained,
    }


def retained_branch_revision(champion_repository: Path, record: dict[str, Any]) -> str:
    champion = _real_absolute_directory(champion_repository, "champion repository")
    record = validate_worktree_record(record, champion_repository=champion)
    revision = (
        _git(
            champion,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"refs/heads/{record['branch']}^{{commit}}",
            allow_failure=True,
        )
        .decode()
        .strip()
    )
    if revision != record["champion_revision"]:
        raise WorkspaceError("retained trial branch identity is missing or changed")
    return revision


def commit_candidate(
    champion_repository: Path,
    record: dict[str, Any],
    diff: dict[str, Any],
    *,
    packet_id: str,
) -> dict[str, Any]:
    """Create one deterministic candidate commit on the exact trial branch."""

    champion = _real_absolute_directory(champion_repository, "champion repository")
    record = validate_worktree_record(record, champion_repository=champion)
    worktree = _real_absolute_directory(Path(record["worktree_path"]), "worktree")
    inspection = inspect_worktree(champion, record)
    if (
        not inspection["resumable"]
        or inspection["revision"] != record["champion_revision"]
        or inspection["tree"] != record["champion_tree"]
    ):
        raise WorkspaceError("candidate worktree is not based on its exact champion")
    if (
        not isinstance(diff, dict)
        or diff.get("status") != "passed"
        or not isinstance(diff.get("paths"), list)
        or not diff["paths"]
        or diff.get("snapshot", {}).get("snapshot_id") is None
    ):
        raise WorkspaceError("candidate diff is not a passed bound record")
    paths = [safe_relative_path(path) for path in diff["paths"]]
    if len(paths) != len(set(paths)):
        raise WorkspaceError("candidate diff repeats a changed path")
    if (
        not isinstance(packet_id, str)
        or re.fullmatch(r"1220[0-9a-f]{64}", packet_id) is None
    ):
        raise WorkspaceError("candidate packet identity is invalid")
    _git(worktree, "add", "--", *paths)
    tree = _git(worktree, "write-tree").decode().strip()
    if GIT_OBJECT.fullmatch(tree) is None or tree == record["champion_tree"]:
        raise WorkspaceError("candidate index did not produce a distinct Git tree")
    epoch_text = (
        _git(
            champion,
            "show",
            "-s",
            "--format=%ct",
            record["champion_revision"],
        )
        .decode()
        .strip()
    )
    if not epoch_text.isdecimal():
        raise WorkspaceError("champion commit timestamp is invalid")
    environment = {
        "GIT_AUTHOR_DATE": f"@{epoch_text} +0000",
        "GIT_AUTHOR_EMAIL": "refinement@cigar.invalid",
        "GIT_AUTHOR_NAME": "CIGAR Refinement",
        "GIT_COMMITTER_DATE": f"@{epoch_text} +0000",
        "GIT_COMMITTER_EMAIL": "refinement@cigar.invalid",
        "GIT_COMMITTER_NAME": "CIGAR Refinement",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    message = (
        f"refinement candidate {record['trial_id']}\n\n"
        f"Task-Packet: {packet_id}\n"
        f"Diff-Snapshot: {diff['snapshot']['snapshot_id']}\n"
    ).encode()
    try:
        result = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "commit-tree",
                tree,
                "-p",
                record["champion_revision"],
            ],
            cwd=worktree,
            input=message,
            env=environment,
            capture_output=True,
            timeout=120,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkspaceError("candidate commit-tree operation failed") from error
    if result.returncode != 0 or result.stderr or len(result.stdout) > 256:
        raise WorkspaceError("candidate commit-tree operation was not clean")
    revision = result.stdout.decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(revision) is None:
        raise WorkspaceError("candidate commit identity is invalid")
    _git(
        worktree,
        "update-ref",
        f"refs/heads/{record['branch']}",
        revision,
        record["champion_revision"],
    )
    candidate = repository_identity(worktree, require_clean=True)
    if (
        candidate["revision"] != revision
        or candidate["tree"] != tree
        or candidate["branch"] != record["branch"]
        or candidate["common_dir"] != record["git_common_dir"]
    ):
        raise WorkspaceError("candidate branch does not reproduce the committed tree")
    parent = _git(worktree, "rev-parse", "--verify", f"{revision}^").decode().strip()
    if parent != record["champion_revision"]:
        raise WorkspaceError("candidate commit parent is not the champion")
    return {
        "schema_version": "cigar.refinement-candidate-commit.v1",
        "trial_id": record["trial_id"],
        "branch": record["branch"],
        "revision": revision,
        "tree": tree,
        "parent_revision": parent,
        "packet_id": packet_id,
        "diff_snapshot_id": diff["snapshot"]["snapshot_id"],
    }


def clean_candidate_worktree(
    champion_repository: Path,
    record: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Remove an exact clean candidate worktree while retaining its branch."""

    champion = _real_absolute_directory(champion_repository, "champion repository")
    record = validate_worktree_record(record, champion_repository=champion)
    expected = {
        "trial_id",
        "branch",
        "revision",
        "tree",
        "parent_revision",
        "packet_id",
        "diff_snapshot_id",
        "schema_version",
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != expected
        or candidate["schema_version"] != "cigar.refinement-candidate-commit.v1"
        or candidate["trial_id"] != record["trial_id"]
        or candidate["branch"] != record["branch"]
        or candidate["parent_revision"] != record["champion_revision"]
    ):
        raise WorkspaceError("candidate cleanup record is malformed")
    path = _real_absolute_directory(Path(record["worktree_path"]), "worktree")
    isolated = repository_identity(path, require_clean=True)
    if (
        isolated["revision"] != candidate["revision"]
        or isolated["tree"] != candidate["tree"]
        or isolated["branch"] != record["branch"]
        or isolated["common_dir"] != record["git_common_dir"]
    ):
        raise WorkspaceError("candidate worktree identity changed before cleanup")
    champion_before = repository_identity(champion, require_clean=True)
    _git(champion, "worktree", "remove", str(path))
    champion_after = repository_identity(champion, require_clean=True)
    if champion_after != champion_before or path.exists():
        raise WorkspaceError(
            "candidate cleanup changed the champion or left the worktree"
        )
    revision = (
        _git(
            champion,
            "rev-parse",
            "--verify",
            f"refs/heads/{record['branch']}^{{commit}}",
        )
        .decode()
        .strip()
    )
    if revision != candidate["revision"]:
        raise WorkspaceError("candidate branch was not retained exactly")
    return {
        "status": "cleaned",
        "trial_id": record["trial_id"],
        "branch_retained": record["branch"],
        "branch_revision": revision,
    }


def _decode_paths(payload: bytes) -> set[str]:
    values: set[str] = set()
    for encoded in payload.split(b"\0"):
        if not encoded:
            continue
        try:
            path = encoded.decode("utf-8", errors="strict")
            values.add(safe_relative_path(path))
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkspaceError("changed path is not portable and safe") from error
    return values


def _tracked_changed_paths(repository: Path) -> set[str]:
    return _decode_paths(
        _git(
            repository,
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "HEAD",
            "--",
        )
    )


def _untracked_paths(repository: Path) -> set[str]:
    return _decode_paths(
        _git(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        )
    )


def _changed_paths(repository: Path) -> list[str]:
    result = sorted(_tracked_changed_paths(repository) | _untracked_paths(repository))
    if len(result) > MAXIMUM_CHANGED_PATHS:
        raise WorkspaceError("changed path inventory exceeded its bound")
    return result


def worktree_snapshot(repository: Path) -> dict[str, Any]:
    root = _real_absolute_directory(repository, "worktree")
    identity_record = repository_identity(root, require_clean=False)
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--no-renames",
    )
    diff = _git(
        root,
        "diff",
        "--binary",
        "--no-ext-diff",
        "--no-renames",
        "HEAD",
        "--",
    )
    bindings: list[dict[str, Any]] = []
    total_bytes = 0
    for relative in _changed_paths(root):
        path = root / relative
        if not path.exists():
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise WorkspaceError("changed path is a link, directory, or special file")
        payload = secure_read(path.absolute(), maximum_bytes=16 * 1024 * 1024)
        total_bytes += len(payload)
        if total_bytes > MAXIMUM_SNAPSHOT_BYTES:
            raise WorkspaceError("changed file snapshot exceeded its byte bound")
        bindings.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    snapshot: dict[str, Any] = {
        "source": {
            "revision": identity_record["revision"],
            "tree": identity_record["tree"],
            "branch": identity_record["branch"],
        },
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "changed_paths": _changed_paths(root),
        "file_bindings": bindings,
    }
    snapshot["snapshot_id"] = identity(snapshot)
    return snapshot


@dataclass(frozen=True)
class DiffPolicy:
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    maximum_files: int
    maximum_lines: int

    def validate(self) -> None:
        if not self.allowed_paths or len(self.allowed_paths) > 1024:
            raise WorkspaceError("diff policy allowed-path inventory is invalid")
        if len(self.forbidden_paths) > 1024:
            raise WorkspaceError("diff policy forbidden-path inventory is invalid")
        for path in (*self.allowed_paths, *self.forbidden_paths):
            safe_relative_path(path)
        if len(set(self.allowed_paths)) != len(self.allowed_paths) or len(
            set(self.forbidden_paths)
        ) != len(self.forbidden_paths):
            raise WorkspaceError("diff policy path inventories contain duplicates")
        if (
            isinstance(self.maximum_files, bool)
            or not isinstance(self.maximum_files, int)
            or isinstance(self.maximum_lines, bool)
            or not isinstance(self.maximum_lines, int)
            or not 1 <= self.maximum_files <= 10000
            or not 1 <= self.maximum_lines <= 1000000
        ):
            raise WorkspaceError("diff policy budget is invalid")


def _covered(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for prefix in prefixes
    )


def validate_diff(repository: Path, policy: DiffPolicy) -> dict[str, Any]:
    policy.validate()
    root = _real_absolute_directory(repository, "worktree")
    paths = _changed_paths(root)
    if len(paths) > policy.maximum_files:
        raise WorkspaceError("changed file count exceeds the diff budget")
    for relative in paths:
        if not _covered(relative, policy.allowed_paths):
            raise WorkspaceError("changed path is outside the allowlist")
        if _covered(relative, policy.forbidden_paths):
            raise WorkspaceError("changed path intersects the denylist")
        path = root / relative
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise WorkspaceError(
                    "changed path is a link, directory, or special file"
                )
    numstat = _git(root, "diff", "--numstat", "-z", "--no-renames", "HEAD", "--")
    lines = 0
    for record in numstat.split(b"\0"):
        if not record:
            continue
        fields = record.split(b"\t", 2)
        if len(fields) != 3:
            raise WorkspaceError("Git numstat output is malformed")
        try:
            added = fields[0].decode("ascii")
            deleted = fields[1].decode("ascii")
            relative = fields[2].decode("utf-8", errors="strict")
            safe_relative_path(relative)
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkspaceError("Git numstat path is unsafe") from error
        if added == "-" or deleted == "-":
            raise WorkspaceError("binary changes are not accepted")
        if not added.isdecimal() or not deleted.isdecimal():
            raise WorkspaceError("Git numstat counts are malformed")
        try:
            lines += int(added) + int(deleted)
        except ValueError as error:
            raise WorkspaceError("Git numstat counts are malformed") from error
    for relative in sorted(_untracked_paths(root)):
        path = root / relative
        if path.exists():
            payload = secure_read(path.absolute(), maximum_bytes=16 * 1024 * 1024)
            if b"\0" in payload:
                raise WorkspaceError("binary changes are not accepted")
            lines += payload.count(b"\n") + (
                1 if payload and not payload.endswith(b"\n") else 0
            )
    if lines > policy.maximum_lines:
        raise WorkspaceError("changed line count exceeds the diff budget")
    return {
        "status": "passed",
        "changed_files": len(paths),
        "changed_lines": lines,
        "paths": paths,
        "snapshot": worktree_snapshot(root),
        "policy_sha256": hashlib.sha256(
            canonical_bytes(
                {
                    "allowed_paths": list(policy.allowed_paths),
                    "forbidden_paths": list(policy.forbidden_paths),
                    "maximum_files": policy.maximum_files,
                    "maximum_lines": policy.maximum_lines,
                }
            )
        ).hexdigest(),
    }
