"""Bounded local stdio client with exact identity and per-child resource receipts."""
import gzip
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


class Worker:
    def __init__(self, binary, version, trace, *, domain, limits=None):
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        self.trace_file = Path(trace).open("xb")
        self.trace = gzip.GzipFile(filename="", fileobj=self.trace_file, mode="wb", mtime=0)
        self.index, self.tag = 0, "init"
        started = time.perf_counter_ns()
        hello, _ = self.ok({"op": "init", "domain": domain, "limits": limits or {}})
        self.startup_ms = (time.perf_counter_ns() - started) / 1e6
        assert hello["core_version"] == version and hello["protocol"] == "cigar.context-worker.v1", hello

    def call(self, command, *, unsupported_probe=False):
        self.index += 1
        started = time.perf_counter_ns()
        request = {"id": self.index, "command": command}
        self.process.stdin.write(canonical(request) + b"\n")
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 30)[0]:
            raise TimeoutError("worker did not respond within 30 seconds")
        line = self.process.stdout.readline(64 * 1024 * 1024 + 1)
        if not line.endswith(b"\n"):
            raise RuntimeError("worker terminated or returned an oversized frame")
        reply = json.loads(line)
        elapsed = (time.perf_counter_ns() - started) / 1e6
        if reply.get("id") != self.index and not (unsupported_probe and reply == {"id": None, "ok": False, "error": "InvalidInput"}):
            raise RuntimeError("worker response correlation mismatch")
        self.trace.write(canonical({"tag": self.tag, "request": request, "reply": reply, "rpc_ms": elapsed}) + b"\n")
        return reply, elapsed

    def ok(self, command):
        reply, elapsed = self.call(command)
        if not reply["ok"]:
            raise RuntimeError(reply)
        return reply["result"], elapsed

    def close(self):
        self.process.stdin.close()
        deadline = time.monotonic() + 5
        while True:
            pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() >= deadline:
                self.process.kill()
                pid, status, usage = os.wait4(self.process.pid, 0)
                break
            time.sleep(.01)
        self.process.returncode = os.waitstatus_to_exitcode(status)
        self.process.stdout.close()
        self.trace.close()
        self.trace_file.close()
        self.stderr.seek(0)
        error = self.stderr.read().decode()
        self.stderr.close()
        if self.process.returncode:
            raise RuntimeError(f"worker exit {self.process.returncode}: {error}")
        return {"peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime, "startup_ms": self.startup_ms}
