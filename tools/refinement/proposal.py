"""Controller-owned proposal tool loop and bounded repair policy."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .adapters import AdapterError, BaseAdapter, validate_action
from .canonical import canonical_bytes, identity, safe_relative_path
from .commands import CommandRegistry, run_named

MAX_TOOL_CONTENT = 1024 * 1024
MAX_SEARCH_CONTENT = 256 * 1024
MAX_FALLBACK_SEARCH_BYTES = 8 * 1024 * 1024
MAX_FALLBACK_SEARCH_MATCHES = 200
PATCH_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
FORBIDDEN_PATCH_MARKERS = (
    "GIT binary patch",
    "Binary files ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "new file mode 120000",
)
GIT_INSPECTIONS: dict[str, tuple[str, ...]] = {
    "status": ("status", "--porcelain=v1", "--untracked-files=all", "--no-renames"),
    "diff": ("diff", "--no-ext-diff", "--no-renames", "--"),
    "diff-stat": ("diff", "--no-ext-diff", "--no-renames", "--stat", "--"),
}


class ProposalError(RuntimeError):
    """The proposal requested an unsafe action or exhausted its bounded loop."""


def _under(path: str, roots: list[str]) -> bool:
    selected = PurePosixPath(path)
    return any(
        selected == PurePosixPath(root) or PurePosixPath(root) in selected.parents
        for root in roots
    )


def allowed_path(packet: dict[str, Any], path: str) -> str:
    try:
        path = safe_relative_path(path)
    except ValueError as error:
        raise ProposalError("proposal path is unsafe") from error
    if not _under(path, packet["allowed_paths"]):
        raise ProposalError("proposal path is outside allowed roots")
    if _under(path, packet["forbidden_paths"]):
        raise ProposalError("proposal path is forbidden")
    return path


def prompt_manifest(prompt_paths: list[Path]) -> list[str]:
    digests: list[str] = []
    for path in prompt_paths:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise ProposalError("prompt path is not an absolute real file")
        payload = path.read_bytes()
        if not payload or len(payload) > MAX_TOOL_CONTENT:
            raise ProposalError("prompt template is empty or oversized")
        digests.append("1220" + hashlib.sha256(payload).hexdigest())
    if len(set(digests)) != len(digests):
        raise ProposalError("prompt templates are not distinct")
    return digests


def context_pack(
    task_packet: dict[str, Any],
    prompt_paths: list[Path],
    resources: dict[str, bytes],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for name in sorted(resources):
        payload = resources[name]
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", name)
            or not isinstance(payload, bytes)
            or len(payload) > MAX_TOOL_CONTENT
        ):
            raise ProposalError("context resource is invalid")
        entries.append(
            {
                "name": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    record: dict[str, Any] = {
        "schema_version": "cigar.refinement-context-pack.v1",
        "pack_id": "",
        "task_packet_id": task_packet["packet_id"],
        "prompt_digests": prompt_manifest(prompt_paths),
        "resources": entries,
    }
    unsigned = dict(record)
    unsigned.pop("pack_id")
    record["pack_id"] = identity(unsigned)
    return record


def tool_result(
    action_id: str,
    *,
    status: str,
    content: bytes = b"",
    reason: str | None = None,
) -> dict[str, Any]:
    if len(content) > MAX_TOOL_CONTENT:
        raise ProposalError("tool result exceeded its byte bound")
    try:
        text = content.decode("utf-8", errors="strict") if content else None
    except UnicodeDecodeError as error:
        raise ProposalError("tool result is not UTF-8") from error
    return {
        "schema_version": "cigar.refinement-tool-result.v1",
        "action_id": action_id,
        "status": status,
        "content": text,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "content_bytes": len(content),
        "reason": reason,
    }


def content_free_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_id": result["action_id"],
        "status": result["status"],
        "content_sha256": result["content_sha256"],
        "content_bytes": result["content_bytes"],
        "reason": result["reason"],
    }


class ProposalController:
    """Execute strict model actions against one already-isolated worktree."""

    def __init__(
        self,
        *,
        worktree: Path,
        task_packet: dict[str, Any],
        adapter: BaseAdapter,
        registry: CommandRegistry,
        command_state: Path,
        context_resources: dict[str, bytes] | None = None,
        maximum_repairs: int = 2,
    ) -> None:
        if (
            not worktree.is_absolute()
            or worktree.is_symlink()
            or worktree.resolve(strict=True) != worktree
            or not worktree.is_dir()
        ):
            raise ProposalError("proposal worktree must be an absolute real directory")
        if not 0 <= maximum_repairs <= 2:
            raise ProposalError("repair limit exceeds policy")
        self.worktree = worktree
        self.packet = task_packet
        self.adapter = adapter
        self.registry = registry
        self.command_state = command_state
        self.resources = dict(context_resources or {})
        self.maximum_repairs = maximum_repairs
        self.repairs = 0
        self.failed_gates: set[str] = set()
        self.transcript: list[dict[str, Any]] = []
        self.patch_digests: list[str] = []
        self.failed_usage: dict[str, Any] | None = None

    def _file(self, relative: str, *, must_exist: bool = True) -> Path:
        relative = allowed_path(self.packet, relative)
        candidate = self.worktree / relative
        if candidate.is_symlink():
            raise ProposalError("proposal path is a symlink")
        try:
            resolved = candidate.resolve(strict=must_exist)
        except OSError as error:
            raise ProposalError("proposal path cannot be resolved") from error
        if resolved != candidate or self.worktree not in resolved.parents:
            raise ProposalError("proposal path escapes the worktree")
        return candidate

    @staticmethod
    def _run(
        argv: list[str],
        *,
        cwd: Path,
        input_data: bytes | None = None,
        allowed_returncodes: frozenset[int] = frozenset({0}),
    ) -> bytes:
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                input=input_data,
                capture_output=True,
                timeout=60,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ProposalError("controller operation could not execute") from error
        output = result.stdout + result.stderr
        if len(output) > MAX_TOOL_CONTENT:
            raise ProposalError("controller operation output exceeded its bound")
        if result.returncode not in allowed_returncodes:
            raise ProposalError("controller operation failed")
        return output

    def _search(self, action: dict[str, Any]) -> bytes:
        root = self._file(action["path"])
        if shutil.which("rg") is None:
            return self._fallback_search(root, action["query"])
        result = self._run(
            [
                "rg",
                "--fixed-strings",
                "--line-number",
                "--no-heading",
                "--color=never",
                "--max-count=200",
                "--",
                action["query"],
                str(root),
            ],
            cwd=self.worktree,
            allowed_returncodes=frozenset({0, 1}),
        )
        if len(result) > MAX_SEARCH_CONTENT:
            raise ProposalError("search result exceeded its smaller bound")
        return result

    def _fallback_search(self, root: Path, query: str) -> bytes:
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = sorted(root.rglob("*"))
        else:
            raise ProposalError("search target is not a regular file or directory")
        output = bytearray()
        scanned_bytes = 0
        matches = 0
        for candidate in candidates:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                if candidate.resolve(strict=True) != candidate:
                    raise ProposalError("search target contains an unsafe path")
                payload = candidate.read_bytes()
            except OSError as error:
                raise ProposalError("search target cannot be read") from error
            scanned_bytes += len(payload)
            if scanned_bytes > MAX_FALLBACK_SEARCH_BYTES:
                raise ProposalError("fallback search exceeded its scan bound")
            try:
                lines = payload.decode("utf-8", errors="strict").splitlines()
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if query not in line:
                    continue
                record = f"{candidate}:{line_number}:{line}\n".encode()
                if len(output) + len(record) > MAX_SEARCH_CONTENT:
                    raise ProposalError("search result exceeded its smaller bound")
                output.extend(record)
                matches += 1
                if matches >= MAX_FALLBACK_SEARCH_MATCHES:
                    return bytes(output)
        return bytes(output)

    def _read(self, action: dict[str, Any]) -> bytes:
        path = self._file(action["path"])
        if not path.is_file():
            raise ProposalError("read target is not a regular file")
        data = path.read_bytes()
        if len(data) > MAX_TOOL_CONTENT:
            raise ProposalError("read target exceeds its byte bound")
        try:
            lines = data.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise ProposalError("read target is not UTF-8") from error
        start = action["start_line"] - 1
        selected = "\n".join(lines[start : start + action["max_lines"]])
        return (selected + ("\n" if selected else "")).encode()

    def _inspect_git(self, action: dict[str, Any]) -> bytes:
        arguments = GIT_INSPECTIONS.get(action["query"])
        if arguments is None:
            raise ProposalError("Git inspection is not allowlisted")
        return self._run(["git", "--no-replace-objects", *arguments], cwd=self.worktree)

    def _validate_patch(self, patch: str) -> bytes:
        payload = patch.encode("utf-8", errors="strict")
        if (
            len(payload) > MAX_TOOL_CONTENT
            or "\x00" in patch
            or any(marker in patch for marker in FORBIDDEN_PATCH_MARKERS)
        ):
            raise ProposalError("patch is oversized or uses a forbidden feature")
        paths: list[str] = []
        for line in patch.splitlines():
            match = PATCH_HEADER.fullmatch(line)
            if match is not None:
                if match.group(1) != match.group(2):
                    raise ProposalError("patch rename is forbidden")
                paths.append(allowed_path(self.packet, match.group(1)))
        if not paths or len(paths) != len(set(paths)):
            raise ProposalError("patch paths are absent or duplicated")
        if len(paths) > self.packet["budgets"]["files"]:
            raise ProposalError("patch exceeds its file budget")
        changed = sum(
            1
            for line in patch.splitlines()
            if (line.startswith("+") and not line.startswith("+++"))
            or (line.startswith("-") and not line.startswith("---"))
        )
        if changed > self.packet["budgets"]["lines"]:
            raise ProposalError("patch exceeds its line budget")
        return payload

    def _apply_patch(self, action: dict[str, Any]) -> bytes:
        payload = self._validate_patch(action["patch"])
        self._run(
            [
                "git",
                "--no-replace-objects",
                "apply",
                "--check",
                "--whitespace=error-all",
                "-",
            ],
            cwd=self.worktree,
            input_data=payload,
        )
        self._run(
            ["git", "--no-replace-objects", "apply", "--whitespace=error-all", "-"],
            cwd=self.worktree,
            input_data=payload,
        )
        digest = hashlib.sha256(payload).hexdigest()
        self.patch_digests.append(digest)
        return canonical_bytes({"patch_sha256": digest, "bytes": len(payload)})

    def _run_gate(self, action: dict[str, Any]) -> tuple[bytes, bool]:
        gate = action["gate"]
        if gate not in self.packet["named_gates"]:
            raise ProposalError("gate is not present in the task packet")
        result = run_named(
            self.registry, gate, cwd=self.worktree, state=self.command_state
        )
        passed = result["status"] == "passed"
        safe = {
            key: result[key]
            for key in (
                "command_id",
                "command_sha256",
                "exit_code",
                "timed_out",
                "output_overflow",
                "stdout_bytes",
                "stdout_sha256",
                "stderr_bytes",
                "stderr_sha256",
                "status",
            )
        }
        if not passed:
            if gate in self.failed_gates:
                raise ProposalError("the same focused-gate failure repeated")
            if self.repairs >= self.maximum_repairs:
                raise ProposalError("repair-cycle limit exhausted")
            self.failed_gates.add(gate)
            self.repairs += 1
        return canonical_bytes(safe), passed

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        action = validate_action(action)
        try:
            if action["kind"] == "search":
                content = self._search(action)
                result = tool_result(
                    action["action_id"], status="passed", content=content
                )
            elif action["kind"] == "read":
                content = self._read(action)
                result = tool_result(
                    action["action_id"], status="passed", content=content
                )
            elif action["kind"] == "inspect_git":
                content = self._inspect_git(action)
                result = tool_result(
                    action["action_id"], status="passed", content=content
                )
            elif action["kind"] == "apply_patch":
                content = self._apply_patch(action)
                result = tool_result(
                    action["action_id"], status="passed", content=content
                )
            elif action["kind"] == "run_gate":
                content, passed = self._run_gate(action)
                result = tool_result(
                    action["action_id"],
                    status="passed" if passed else "failed",
                    content=content,
                    reason=None if passed else "named_gate_failed",
                )
            elif action["kind"] == "request_context":
                resource = action["resource"]
                if resource not in self.resources:
                    raise ProposalError("context resource is not allowlisted")
                result = tool_result(
                    action["action_id"],
                    status="passed",
                    content=self.resources[resource],
                )
            else:
                result = tool_result(action["action_id"], status="passed")
        except ProposalError as error:
            result = tool_result(
                action["action_id"], status="denied", reason=str(error)
            )
        self.transcript.append(
            {
                "action_id": action["action_id"],
                "kind": action["kind"],
                "result": content_free_result(result),
            }
        )
        return result

    def run(self) -> dict[str, Any]:
        started = time.monotonic()
        session_id = self.adapter.start(self.packet)
        pending: dict[str, Any] | None = None
        terminal: dict[str, Any] | None = None
        try:
            while terminal is None:
                if time.monotonic() - started > self.packet["budgets"]["wall_seconds"]:
                    raise ProposalError("proposal wall-time budget exceeded")
                if len(self.transcript) >= self.packet["budgets"]["turns"]:
                    raise ProposalError("proposal turn budget exceeded")
                action = self.adapter.next(session_id, pending)
                if action["kind"] in {"finish", "abandon"}:
                    terminal = action
                    final_result = self.execute(action)
                    if final_result["status"] == "denied":
                        raise ProposalError(final_result["reason"])
                else:
                    pending = self.execute(action)
                    if pending["status"] == "denied":
                        raise ProposalError(pending["reason"])
        except (AdapterError, ProposalError):
            self.adapter.cancel(session_id)
            self.failed_usage = self.adapter.usage(session_id)
            raise
        usage = self.adapter.usage(session_id)
        if (
            usage["turns"] > self.packet["budgets"]["turns"]
            or usage["input_tokens"] > self.packet["budgets"]["input_tokens"]
            or usage["output_tokens"] > self.packet["budgets"]["output_tokens"]
            or usage["cost_usd"] > self.packet["budgets"]["cost_usd"]
        ):
            raise ProposalError("proposal usage exceeded the packet budget")
        record = {
            "schema_version": "cigar.refinement-proposal-outcome.v1",
            "session_id": session_id,
            "terminal_kind": terminal["kind"],
            "summary": terminal["summary"],
            "reason": terminal["reason"],
            "repair_cycles": self.repairs,
            "patch_digests": list(self.patch_digests),
            "transcript": list(self.transcript),
            "usage_id": usage["usage_id"],
            "usage": usage,
        }
        record["outcome_id"] = identity(record)
        return record
