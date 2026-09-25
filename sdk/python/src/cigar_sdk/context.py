"""Persistent local Rust context graphs. No network, implicit ingestion, or downloads."""

from __future__ import annotations

import json
import math
import queue
import subprocess
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Any, Self, cast

from cigar_sdk.context_types import (
    LocalAnswerAssessment,
    LocalAnswerDraft,
    LocalAnswerPolicy,
    LocalCitation,
    LocalClaimReview,
    LocalContextDelta,
    LocalContextLimits,
    LocalContextPrompt,
    LocalContextRequest,
    LocalContextResult,
    LocalContextSnapshot,
    LocalDocument,
    LocalEdgeKind,
    LocalGraphStats,
    LocalSourceUpdate,
)
from cigar_sdk.local_runtime import (
    LOCAL_CONTEXT_CORE_VERSION as LOCAL_CONTEXT_CORE_VERSION,
)
from cigar_sdk.local_runtime import (
    LOCAL_CONTEXT_PROTOCOL as LOCAL_CONTEXT_PROTOCOL,
)
from cigar_sdk.local_runtime import (
    LocalContextCapabilities as LocalContextCapabilities,
)
from cigar_sdk.local_runtime import (
    LocalContextError as LocalContextError,
)
from cigar_sdk.local_runtime import (
    bundled_worker as _bundled_worker,
)
from cigar_sdk.local_runtime import (
    get_local_context_capabilities as get_local_context_capabilities,
)
from cigar_sdk.local_runtime import (
    resolve_local_worker,
)

_MAX_FRAME = 32 * 1024 * 1024
_MAX_RESPONSE = 64 * 1024 * 1024


class LocalContextGraph:
    """One graph, privacy domain, and bounded cache per worker process.

    Use a context manager or close(). ``worker_path`` is an explicit trusted executable;
    it is never searched in PATH. Calls are serialized. The timeout includes lock wait
    and pipe I/O. A lock-wait timeout does not interrupt another caller's operation.
    A transport timeout closes this graph, because mutation outcome may be unknown.
    """

    def __init__(
        self, domain: str, *, limits: LocalContextLimits | None = None,
        worker_path: str | Path | None = None, timeout: float = 30.0,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0 or timeout > threading.TIMEOUT_MAX:
            raise LocalContextError("InvalidInput")
        binary = resolve_local_worker(worker_path) if worker_path is not None else _bundled_worker()
        self._timeout = timeout
        self._closed = False
        self._lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._next_id = 0
        self._jobs: queue.Queue[tuple[bytes, queue.Queue[bytes | None]] | None] = queue.Queue(maxsize=1)
        try:
            self._process = subprocess.Popen(
                [str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                shell=False, close_fds=True,
            )
        except OSError:
            raise LocalContextError("WorkerUnavailable") from None
        self._thread = threading.Thread(target=self._exchange_loop, name="cigar-context-stdio", daemon=True)
        self._thread.start()
        try:
            hello = self._call({"op": "init", "domain": domain, "limits": limits or {}})
            if (
                not isinstance(hello, dict) or hello.get("protocol") != LOCAL_CONTEXT_PROTOCOL
                or hello.get("core_version") != LOCAL_CONTEXT_CORE_VERSION
                or hello.get("max_frame_bytes") != _MAX_FRAME
                or hello.get("max_response_bytes") != _MAX_RESPONSE
            ):
                raise LocalContextError("IncompatibleWorker")
        except BaseException:
            self.close()
            raise

    def _exchange_loop(self) -> None:
        stdin, stdout = self._process.stdin, self._process.stdout
        assert stdin is not None and stdout is not None
        while (job := self._jobs.get()) is not None:
            frame, response = job
            try:
                stdin.write(frame)
                stdin.flush()
                value = stdout.readline(_MAX_RESPONSE + 1)
                response.put_nowait(value)
            except (OSError, ValueError):
                response.put_nowait(None)

    def _call(self, command: dict[str, Any]) -> Any:
        deadline = time.monotonic() + self._timeout
        if not self._lock.acquire(timeout=self._timeout):
            raise LocalContextError("Busy")
        try:
            if self._closed:
                raise LocalContextError("Closed")
            self._next_id = (self._next_id % 4_294_967_295) + 1
            try:
                frame = (json.dumps({"id": self._next_id, "command": command}, ensure_ascii=False,
                                    allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
            except (ValueError, TypeError, UnicodeError, RecursionError):
                raise LocalContextError("InvalidInput") from None
            if len(frame) > _MAX_FRAME:
                raise LocalContextError("LimitExceeded")
            response: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
            self._jobs.put_nowait((frame, response))
            try:
                value = response.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                self.close()
                raise LocalContextError("Timeout") from None
            if not value or len(value) > _MAX_RESPONSE or not value.endswith(b"\n"):
                self.close()
                raise LocalContextError("Transport")
            try:
                reply = json.loads(value)
                if not isinstance(reply, dict) or type(reply.get("ok")) is not bool:
                    raise ValueError
                if reply.get("id") != self._next_id:
                    raise ValueError
                if reply["ok"]:
                    return reply["result"]
                code = reply["error"]
                if code not in {"InvalidInput", "LimitExceeded", "RequiredUnavailable", "BudgetUnsatisfiable",
                                "Tokenizer", "Integrity", "BaseMismatch"}:
                    raise ValueError
            except (ValueError, TypeError, KeyError, RecursionError):
                self.close()
                raise LocalContextError("Transport") from None
            raise LocalContextError(code)
        finally:
            self._lock.release()

    def upsert(self, document: LocalDocument) -> bool:
        return cast(bool, self._call({"op": "upsert", "document": document}))

    def replace_source(self, source: str, documents: list[LocalDocument]) -> LocalSourceUpdate:
        """Atomically replace one source; [] withdraws it. Hard edges remain fail-closed."""
        return cast(LocalSourceUpdate, self._call({"op": "replace_source", "source": source, "documents": documents}))

    def remove(self, node_id: str) -> bool:
        return cast(bool, self._call({"op": "remove", "node_id": node_id}))

    def link(self, from_id: str, to_id: str, kind: LocalEdgeKind) -> bool:
        return cast(bool, self._call({"op": "link", "from": from_id, "to": to_id, "kind": kind}))

    def unlink(self, from_id: str, to_id: str, kind: LocalEdgeKind) -> bool:
        return cast(bool, self._call({"op": "unlink", "from": from_id, "to": to_id, "kind": kind}))

    def compile(self, request: LocalContextRequest) -> LocalContextResult:
        """Return a verified snapshot and Rust-rendered data-role context (not instructions)."""
        return cast(LocalContextResult, self._call({"op": "compile", "request": request}))

    def chunks(self, document: LocalDocument, max_lines: int, overlap_lines: int = 0) -> list[LocalDocument]:
        return cast(list[LocalDocument], self._call({"op": "chunks", "document": document,
                                                    "max_lines": max_lines, "overlap_lines": overlap_lines}))

    def review_keys(self, draft: LocalAnswerDraft) -> list[str]:
        """Bind exact claims to their snapshot for a separate trusted reviewer; no truth judgment."""
        return cast(list[str], self._call({"op": "review_keys", "draft": draft}))

    def check_answer(
        self, request: LocalContextRequest, draft: LocalAnswerDraft,
        reviews: list[LocalClaimReview], policy: LocalAnswerPolicy | None = None,
    ) -> LocalAnswerAssessment:
        """Recompile current authorized context and enforce host-trusted claim reviews.

        Keep reviews/policy outside model control. Only display assessed claims on release.
        Confidence is telemetry, not permission. This does not run a semantic judge.
        """
        return cast(LocalAnswerAssessment, self._call({"op": "check_answer", "request": request,
                    "draft": draft, "reviews": reviews, "policy": policy or {}}))

    def verify(self, snapshot: LocalContextSnapshot) -> LocalContextResult:
        return cast(LocalContextResult, self._call({"op": "verify", "snapshot": snapshot}))

    def prompt_view(self, snapshot: LocalContextSnapshot, max_tokens: int) -> LocalContextPrompt:
        """Compact data-role rendering; retain its citation map and the complete snapshot."""
        return cast(
            LocalContextPrompt, self._call({"op": "prompt_view", "snapshot": snapshot, "max_tokens": max_tokens})
        )

    def verify_prompt(self, prompt: LocalContextPrompt, snapshot: LocalContextSnapshot) -> LocalContextPrompt:
        return cast(LocalContextPrompt, self._call({"op": "verify_prompt", "prompt": prompt, "snapshot": snapshot}))

    def resolve_citation(
        self, reference: str, prompt: LocalContextPrompt, snapshot: LocalContextSnapshot
    ) -> list[LocalCitation]:
        return cast(
            list[LocalCitation],
            self._call({"op": "resolve_citation", "reference": reference, "prompt": prompt, "snapshot": snapshot}),
        )

    def delta(self, base: LocalContextSnapshot, target: LocalContextSnapshot) -> LocalContextDelta:
        return cast(LocalContextDelta, self._call({"op": "delta", "base": base, "target": target}))

    def apply_delta(self, base: LocalContextSnapshot, delta: LocalContextDelta) -> LocalContextResult:
        return cast(LocalContextResult, self._call({"op": "apply_delta", "base": base, "delta": delta}))

    def stats(self) -> LocalGraphStats:
        return cast(LocalGraphStats, self._call({"op": "stats"}))

    def clear_cache(self) -> None:
        self._call({"op": "clear_cache"})

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            if self._process.poll() is None:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            self._process.wait(timeout=5)
            # Killing the child unblocks the single I/O thread, including blocked writes.
            self._jobs.put(None, timeout=5)
            self._thread.join(timeout=5)
            if self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                except OSError:
                    pass
            if self._process.stdout is not None:
                self._process.stdout.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self.close()
