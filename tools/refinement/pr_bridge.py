#!/usr/bin/env python3
"""Verify and bridge one retained CIGAR candidate into a draft GitHub PR."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import http.client
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    loads,
    sha256_bytes,
)
from tools.refinement.schema import SchemaRegistry
from tools.refinement.workspace import GIT_OBJECT, WorkspaceError, repository_identity

MAXIMUM_GIT_OUTPUT = 16 * 1024 * 1024
MAXIMUM_API_BYTES = 1024 * 1024
REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
TOKEN_HANDLE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

GitHubTransport = Callable[
    [str, str, dict[str, str], bytes | None, int],
    tuple[int, dict[str, str], bytes],
]


class DraftPRBridgeError(RuntimeError):
    """The requested draft review is unsafe, stale, ambiguous, or failed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _stdlib_transport(
    method: str,
    endpoint: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: int,
) -> tuple[int, dict[str, str], bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(
        endpoint, data=body, headers=headers, method=method
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(MAXIMUM_API_BYTES + 1)
            return response.status, dict(response.headers.items()), payload
    except urllib.error.HTTPError as error:
        return (
            error.code,
            dict(error.headers.items()),
            error.read(MAXIMUM_API_BYTES + 1),
        )
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as error:
        raise DraftPRBridgeError("GitHub transport failed") from error


def _absolute_repository(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise DraftPRBridgeError("repository must be an absolute real path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DraftPRBridgeError("repository cannot be resolved") from error
    if resolved != path or not path.is_dir():
        raise DraftPRBridgeError("repository must not contain aliases")
    return path


def _git(
    repository: Path,
    *arguments: str,
    allowed_codes: frozenset[int] = frozenset({0}),
) -> bytes:
    environment = dict(os.environ)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=environment,
            timeout=120,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DraftPRBridgeError("Git command could not be executed") from error
    if (
        len(result.stdout) > MAXIMUM_GIT_OUTPUT
        or len(result.stderr) > MAXIMUM_GIT_OUTPUT
    ):
        raise DraftPRBridgeError("Git command output exceeded its bound")
    if result.returncode not in allowed_codes:
        raise DraftPRBridgeError("Git command failed")
    return result.stdout


def _schema(repository: Path) -> SchemaRegistry:
    return SchemaRegistry(repository / "schemas" / "refinement")


def verify_payload(repository: Path, payload: dict[str, Any]) -> None:
    try:
        _schema(repository).validate("pr-payload-v1.schema.json", payload)
    except ValueError as error:
        raise DraftPRBridgeError("draft PR payload is malformed") from error
    unsigned = dict(payload)
    payload_id = unsigned.pop("payload_id")
    if (
        payload_id != identity(unsigned)
        or payload["branch"] != f"refine/trial-{payload['trial_id']}"
        or payload["base_revision"] == payload["candidate_revision"]
    ):
        raise DraftPRBridgeError("draft PR payload identity is invalid")


def _validate_ref(repository: Path, branch: str) -> None:
    if (
        BRANCH.fullmatch(branch) is None
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or branch.endswith(("/", ".", ".lock"))
        or "/." in branch
    ):
        raise DraftPRBridgeError("Git branch is malformed")
    _git(repository, "check-ref-format", f"refs/heads/{branch}")


def _resolve(repository: Path, reference: str, suffix: str = "commit") -> str:
    value = (
        _git(
            repository,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{reference}^{{{suffix}}}",
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if GIT_OBJECT.fullmatch(value) is None:
        raise DraftPRBridgeError("Git object identity is malformed")
    return value


def _verify_local_candidate(repository: Path, payload: dict[str, Any]) -> None:
    try:
        repository_identity(repository, require_clean=True)
    except WorkspaceError as error:
        raise DraftPRBridgeError(
            "repository identity is unsafe or the worktree is not clean"
        ) from error
    _validate_ref(repository, payload["branch"])
    branch_revision = _resolve(repository, f"refs/heads/{payload['branch']}")
    candidate_tree = _resolve(repository, payload["candidate_revision"], "tree")
    _resolve(repository, payload["base_revision"])
    parents = (
        _git(
            repository,
            "rev-list",
            "--parents",
            "-n",
            "1",
            payload["candidate_revision"],
        )
        .decode("ascii", errors="strict")
        .split()
    )
    if (
        branch_revision != payload["candidate_revision"]
        or candidate_tree != payload["candidate_tree"]
        or parents != [payload["candidate_revision"], payload["base_revision"]]
    ):
        raise DraftPRBridgeError("retained candidate branch identity changed")


def _github_remote_identity(url: str) -> str | None:
    value: str | None = None
    if url.startswith("git@github.com:"):
        value = url.removeprefix("git@github.com:")
    else:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "github.com"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and not parsed.query
            and not parsed.fragment
        ):
            value = parsed.path.removeprefix("/")
        elif (
            parsed.scheme == "ssh"
            and parsed.hostname == "github.com"
            and parsed.username == "git"
            and parsed.password is None
            and parsed.port in {None, 22}
            and not parsed.query
            and not parsed.fragment
        ):
            value = parsed.path.removeprefix("/")
    if value is None:
        return None
    if value.endswith(".git"):
        value = value[:-4]
    return value if GITHUB_REPOSITORY.fullmatch(value) is not None else None


def _remote_url(
    repository: Path,
    remote: str,
    github_repository: str,
    *,
    allow_non_github_remote: bool,
) -> str:
    if REMOTE_NAME.fullmatch(remote) is None:
        raise DraftPRBridgeError("Git remote name is malformed")
    fetch_urls = (
        _git(repository, "remote", "get-url", "--all", remote)
        .decode("utf-8", errors="strict")
        .splitlines()
    )
    push_urls = (
        _git(repository, "remote", "get-url", "--push", "--all", remote)
        .decode("utf-8", errors="strict")
        .splitlines()
    )
    if (
        len(fetch_urls) != 1
        or len(push_urls) != 1
        or fetch_urls[0] != push_urls[0]
        or len(fetch_urls[0]) > 4096
    ):
        raise DraftPRBridgeError("Git remote URL is ambiguous")
    url = fetch_urls[0]
    remote_identity = _github_remote_identity(url)
    if not allow_non_github_remote and (
        remote_identity is None
        or remote_identity.casefold() != github_repository.casefold()
    ):
        raise DraftPRBridgeError("Git remote does not match the GitHub repository")
    return url


def _ls_remote(repository: Path, remote: str, branch: str) -> str | None:
    _validate_ref(repository, branch)
    output = _git(
        repository,
        "ls-remote",
        "--exit-code",
        "--refs",
        "--heads",
        remote,
        branch,
        allowed_codes=frozenset({0, 2}),
    )
    if not output:
        return None
    lines = output.decode("ascii", errors="strict").splitlines()
    expected_ref = f"refs/heads/{branch}"
    parsed = [line.split("\t") for line in lines]
    if (
        len(parsed) != 1
        or len(parsed[0]) != 2
        or GIT_OBJECT.fullmatch(parsed[0][0]) is None
        or parsed[0][1] != expected_ref
    ):
        raise DraftPRBridgeError("Git remote returned an ambiguous ref")
    return parsed[0][0]


def preview(
    *,
    repository: Path,
    payload: dict[str, Any],
    remote: str,
    base_branch: str,
    github_repository: str,
    title: str,
    body: str,
    allow_non_github_remote: bool = False,
) -> dict[str, Any]:
    """Perform all local and read-only remote checks required before execution."""

    repository = _absolute_repository(repository)
    if GITHUB_REPOSITORY.fullmatch(github_repository) is None:
        raise DraftPRBridgeError("GitHub repository must use owner/name syntax")
    if not 1 <= len(title) <= 256 or not 1 <= len(body) <= 65536:
        raise DraftPRBridgeError("draft PR title or body is outside its bound")
    verify_payload(repository, payload)
    _verify_local_candidate(repository, payload)
    _validate_ref(repository, base_branch)
    remote_url = _remote_url(
        repository,
        remote,
        github_repository,
        allow_non_github_remote=allow_non_github_remote,
    )
    remote_base = _ls_remote(repository, remote, base_branch)
    if remote_base != payload["base_revision"]:
        raise DraftPRBridgeError("remote base branch is missing, advanced, or changed")
    remote_candidate = _ls_remote(repository, remote, payload["branch"])
    if remote_candidate not in {None, payload["candidate_revision"]}:
        raise DraftPRBridgeError("remote candidate branch has a divergent identity")
    body_record = {
        "schema_version": "cigar.refinement-draft-pr-preview.v1",
        "payload_id": payload["payload_id"],
        "operation": "push-exact-candidate-and-create-draft-review",
        "github_repository": github_repository,
        "title": title,
        "body_sha256": sha256_bytes(body.encode("utf-8", errors="strict")),
        "remote": {
            "name": remote,
            "url": remote_url,
            "base_branch": base_branch,
            "base_revision": remote_base,
            "candidate_ref": f"refs/heads/{payload['branch']}",
            "candidate_state": ("absent" if remote_candidate is None else "exact"),
        },
        "source": {
            "base_revision": payload["base_revision"],
            "candidate_revision": payload["candidate_revision"],
            "candidate_tree": payload["candidate_tree"],
            "branch": payload["branch"],
        },
        "merge_authority": False,
        "publication_authority": False,
        "executable": True,
    }
    result = {**body_record, "preview_id": identity(body_record)}
    try:
        _schema(repository).validate("draft-pr-preview-v1.schema.json", result)
    except ValueError as error:
        raise DraftPRBridgeError("draft PR preview is malformed") from error
    return result


def _github_headers(token: str) -> dict[str, str]:
    if not 20 <= len(token) <= 4096 or any(
        ord(character) < 33 or ord(character) > 126 for character in token
    ):
        raise DraftPRBridgeError("GitHub credential is missing or malformed")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "cigar-refinement-draft-pr-bridge/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _api_json(
    transport: GitHubTransport,
    *,
    method: str,
    endpoint: str,
    headers: dict[str, str],
    body: bytes | None,
    expected_status: int,
) -> Any:
    status, _response_headers, payload = transport(method, endpoint, headers, body, 30)
    if len(payload) > MAXIMUM_API_BYTES or status != expected_status:
        raise DraftPRBridgeError(f"GitHub API request failed with HTTP {status}")
    try:
        return loads(payload, maximum_bytes=MAXIMUM_API_BYTES)
    except ValueError as error:
        raise DraftPRBridgeError("GitHub API returned malformed JSON") from error


def _pull_request(
    value: Any,
    *,
    github_repository: str,
    branch: str,
    base_branch: str,
    candidate_revision: str,
    base_revision: str,
    title: str,
    body: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DraftPRBridgeError("GitHub pull request response is not an object")
    try:
        number = value["number"]
        url = value["html_url"]
        draft = value["draft"]
        state = value["state"]
        response_title = value["title"]
        response_body = value["body"]
        maintainer_can_modify = value["maintainer_can_modify"]
        head_ref = value["head"]["ref"]
        head_revision = value["head"]["sha"]
        head_repository = value["head"]["repo"]["full_name"]
        base_ref = value["base"]["ref"]
        response_base_revision = value["base"]["sha"]
        base_repository = value["base"]["repo"]["full_name"]
    except (KeyError, TypeError) as error:
        raise DraftPRBridgeError(
            "GitHub pull request response is incomplete"
        ) from error
    expected_prefix = f"https://github.com/{github_repository}/pull/"
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or not isinstance(url, str)
        or url != f"{expected_prefix}{number}"
        or draft is not True
        or state != "open"
        or response_title != title
        or response_body != body
        or maintainer_can_modify is not False
        or head_ref != branch
        or head_revision != candidate_revision
        or base_ref != base_branch
        or response_base_revision != base_revision
        or not isinstance(head_repository, str)
        or not isinstance(base_repository, str)
        or head_repository.casefold() != github_repository.casefold()
        or base_repository.casefold() != github_repository.casefold()
    ):
        raise DraftPRBridgeError("GitHub pull request identity is not exact")
    return {"number": number, "url": url, "draft": True}


def _find_or_create_pull_request(
    *,
    github_repository: str,
    branch: str,
    base_branch: str,
    candidate_revision: str,
    base_revision: str,
    title: str,
    body: str,
    token: str,
    transport: GitHubTransport,
) -> tuple[dict[str, Any], bool]:
    owner = github_repository.split("/", 1)[0]
    root = f"https://api.github.com/repos/{github_repository}/pulls"
    query = urllib.parse.urlencode(
        {
            "state": "open",
            "head": f"{owner}:{branch}",
            "base": base_branch,
            "per_page": "2",
        }
    )
    headers = _github_headers(token)
    existing = _api_json(
        transport,
        method="GET",
        endpoint=f"{root}?{query}",
        headers=headers,
        body=None,
        expected_status=200,
    )
    if not isinstance(existing, list) or len(existing) > 2:
        raise DraftPRBridgeError("GitHub pull request lookup is ambiguous")
    if existing:
        if len(existing) != 1:
            raise DraftPRBridgeError("multiple open pull requests use the exact branch")
        return (
            _pull_request(
                existing[0],
                github_repository=github_repository,
                branch=branch,
                base_branch=base_branch,
                candidate_revision=candidate_revision,
                base_revision=base_revision,
                title=title,
                body=body,
            ),
            False,
        )
    request = canonical_bytes(
        {
            "base": base_branch,
            "body": body,
            "draft": True,
            "head": f"{owner}:{branch}",
            "maintainer_can_modify": False,
            "title": title,
        }
    )
    created = _api_json(
        transport,
        method="POST",
        endpoint=root,
        headers=headers,
        body=request,
        expected_status=201,
    )
    return (
        _pull_request(
            created,
            github_repository=github_repository,
            branch=branch,
            base_branch=base_branch,
            candidate_revision=candidate_revision,
            base_revision=base_revision,
            title=title,
            body=body,
        ),
        True,
    )


def execute(
    *,
    repository: Path,
    payload: dict[str, Any],
    remote: str,
    base_branch: str,
    github_repository: str,
    title: str,
    body: str,
    confirmation_payload_id: str,
    token: str,
    transport: GitHubTransport = _stdlib_transport,
    allow_non_github_remote: bool = False,
) -> dict[str, Any]:
    """Push one literal commit refspec and create or recover one draft PR."""

    _github_headers(token)
    initial = preview(
        repository=repository,
        payload=payload,
        remote=remote,
        base_branch=base_branch,
        github_repository=github_repository,
        title=title,
        body=body,
        allow_non_github_remote=allow_non_github_remote,
    )
    if confirmation_payload_id != payload["payload_id"]:
        raise DraftPRBridgeError("execution confirmation does not match payload ID")
    pushed = initial["remote"]["candidate_state"] == "absent"
    if pushed:
        _git(
            repository,
            "push",
            "--porcelain",
            "--no-verify",
            remote,
            (f"{payload['candidate_revision']}:refs/heads/{payload['branch']}"),
        )
    after_push = preview(
        repository=repository,
        payload=payload,
        remote=remote,
        base_branch=base_branch,
        github_repository=github_repository,
        title=title,
        body=body,
        allow_non_github_remote=allow_non_github_remote,
    )
    if after_push["remote"]["candidate_state"] != "exact":
        raise DraftPRBridgeError("remote did not retain the exact candidate commit")
    pull_request, created = _find_or_create_pull_request(
        github_repository=github_repository,
        branch=payload["branch"],
        base_branch=base_branch,
        candidate_revision=payload["candidate_revision"],
        base_revision=payload["base_revision"],
        title=title,
        body=body,
        token=token,
        transport=transport,
    )
    final = preview(
        repository=repository,
        payload=payload,
        remote=remote,
        base_branch=base_branch,
        github_repository=github_repository,
        title=title,
        body=body,
        allow_non_github_remote=allow_non_github_remote,
    )
    if final["remote"]["candidate_state"] != "exact":
        raise DraftPRBridgeError("remote candidate changed while opening review")
    body_record = {
        "schema_version": "cigar.refinement-draft-pr-receipt.v1",
        "preview_id": initial["preview_id"],
        "payload_id": payload["payload_id"],
        "github_repository": github_repository,
        "remote": {
            "name": remote,
            "base_branch": base_branch,
            "base_revision": payload["base_revision"],
            "head_branch": payload["branch"],
            "head_revision": payload["candidate_revision"],
            "pushed": pushed,
        },
        "pull_request": {
            **pull_request,
            "created": created,
        },
        "merge_authority": False,
        "publication_authority": False,
    }
    receipt = {**body_record, "receipt_id": identity(body_record)}
    try:
        _schema(repository).validate("draft-pr-receipt-v1.schema.json", receipt)
    except ValueError as error:
        raise DraftPRBridgeError("draft PR receipt is malformed") from error
    return receipt


def _load_payload(repository: Path, path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        raise DraftPRBridgeError("payload must be an absolute real path")
    try:
        resolved = path.resolve(strict=True)
        value = load_file(path)
    except (OSError, ValueError) as error:
        raise DraftPRBridgeError("payload is malformed") from error
    if resolved != path or not isinstance(value, dict):
        raise DraftPRBridgeError("payload must not contain aliases")
    verify_payload(repository, value)
    return value


def _create_new(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir():
        raise DraftPRBridgeError("output must be an absolute create-new path")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o400)
        payload += b"\n"
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise DraftPRBridgeError("output write was incomplete")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
        ):
            raise DraftPRBridgeError("output metadata is unsafe")
    except OSError as error:
        raise DraftPRBridgeError("output cannot be published create-new") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--title")
    parser.add_argument("--body")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-payload-id")
    parser.add_argument("--token-handle", default="GITHUB_TOKEN")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository = _absolute_repository(arguments.repository)
        payload = _load_payload(repository, arguments.payload)
        title = arguments.title or f"refinement: {payload['trial_id']}"
        body = arguments.body or (
            "Automated refinement candidate prepared for review only.\n\n"
            f"- Trial: `{payload['trial_id']}`\n"
            f"- Evaluation: `{payload['evaluation_id']}`\n"
            f"- Payload: `{payload['payload_id']}`\n"
            f"- Candidate: `{payload['candidate_revision']}`\n\n"
            "This bridge has no merge or publication authority."
        )
        if arguments.execute:
            if (
                arguments.confirm_payload_id is None
                or TOKEN_HANDLE.fullmatch(arguments.token_handle) is None
            ):
                raise DraftPRBridgeError(
                    "execution requires an exact payload confirmation and token handle"
                )
            token = os.environ.get(arguments.token_handle, "")
            result = execute(
                repository=repository,
                payload=payload,
                remote=arguments.remote,
                base_branch=arguments.base_branch,
                github_repository=arguments.github_repository,
                title=title,
                body=body,
                confirmation_payload_id=arguments.confirm_payload_id,
                token=token,
            )
        else:
            if arguments.confirm_payload_id is not None:
                raise DraftPRBridgeError(
                    "payload confirmation is accepted only with --execute"
                )
            result = preview(
                repository=repository,
                payload=payload,
                remote=arguments.remote,
                base_branch=arguments.base_branch,
                github_repository=arguments.github_repository,
                title=title,
                body=body,
            )
        encoded = canonical_bytes(result)
        if arguments.output is not None:
            _create_new(arguments.output, encoded)
        sys.stdout.buffer.write(encoded + b"\n")
        return 0
    except (DraftPRBridgeError, OSError, ValueError) as error:
        print(f"draft PR bridge: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
