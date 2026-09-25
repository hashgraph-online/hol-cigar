"""Installed worker discovery, diagnostic failures and the complete offline example."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cigar_sdk import get_local_context_capabilities
from cigar_sdk import local_runtime as runtime
from cigar_sdk.examples.local_workflow import run_local_workflow
from cigar_sdk.native_platforms import NATIVE_PLATFORMS


class LocalRuntimeTests(unittest.TestCase):
    def test_each_platform_selects_its_worker_and_rejects_wrong_target_and_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for identity, metadata in NATIVE_PLATFORMS.items():
                system, machine, *libc = identity.split("-")
                system = {"darwin": "Darwin", "linux": "Linux", "win32": "Windows"}[system]
                machine = {"x64": "AMD64", "arm64": "aarch64"}[machine]
                libc_name = "glibc" if libc == ["gnu"] else ""
                abi = "aarch64-linux-musl" if libc == ["musl"] else ""
                with (
                    self.subTest(platform=identity),
                    patch.object(runtime, "__file__", str(root / "local_runtime.py")),
                    patch.object(runtime.platform, "system", return_value=system),
                    patch.object(runtime.platform, "machine", return_value=machine),
                    patch.object(runtime.platform, "libc_ver", return_value=(libc_name, "2.28")),
                    patch.object(runtime.sysconfig, "get_config_var", return_value=abi),
                ):
                    self.assertEqual(runtime.local_platform(), identity)
                    directory = root / "_native" / identity
                    directory.mkdir(parents=True)
                    binary = directory / metadata["executable"]
                    binary.write_bytes(f"fixture bytes for {identity}".encode())
                    manifest = {
                        "protocol": "cigar.context-worker.v1",
                        "core_version": "0.12.0",
                        "target": metadata["target"],
                        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    }
                    path = directory / "manifest.json"
                    path.write_text(json.dumps(manifest))
                    self.assertEqual(runtime.bundled_worker(), binary)
                    self.assertTrue(runtime.get_local_context_capabilities()["worker_available"])
                    path.write_text(json.dumps(manifest | {"target": "wrong-target"}))
                    self.assertEqual(runtime.get_local_context_capabilities()["error_code"], "WorkerIntegrity")
                    path.write_text(json.dumps(manifest))
                    binary.write_bytes(b"altered")
                    self.assertEqual(runtime.get_local_context_capabilities()["error_code"], "WorkerIntegrity")

    def test_missing_and_unknown_workers_do_not_request_services_or_reflect_paths(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(runtime, "__file__", str(Path(temporary) / "local_runtime.py")),
        ):
            missing = runtime.get_local_context_capabilities()
            self.assertEqual(missing["error_code"], "WorkerUnavailable")
            self.assertIn("HOL services and API keys are not required", missing["guidance"])
            private = Path(temporary) / "PRIVATE_USER_PATH"
            explicit = runtime.get_local_context_capabilities(worker_path=private)
            self.assertEqual(explicit["worker_source"], "explicit")
            self.assertNotIn(str(private), json.dumps(explicit))
            with patch.object(runtime.platform, "system", return_value="FreeBSD"):
                self.assertEqual(runtime.get_local_context_capabilities()["error_code"], "UnsupportedPlatform")
            with (
                patch.object(runtime.platform, "system", return_value="Linux"),
                patch.object(runtime.platform, "libc_ver", return_value=("", "")),
                patch.object(runtime.sysconfig, "get_config_var", return_value=""),
            ):
                self.assertEqual(runtime.get_local_context_capabilities()["error_code"], "UnsupportedPlatform")

    def command(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "cigar_sdk.local_cli", *arguments], capture_output=True, text=True, timeout=15
        )

    def test_doctor_requires_a_real_compile_and_handles_missing_workers(self):
        missing = self.command("doctor", "--json", "--worker", "relative-private-path")
        self.assertEqual(missing.returncode, 1, missing.stderr)
        failure = json.loads(missing.stdout)
        self.assertEqual(failure["error_code"], "WorkerUnavailable")
        self.assertFalse(failure["compile_verified"])
        self.assertNotIn("relative-private-path", missing.stdout)
        worker = os.environ.get("CIGAR_TEST_WORKER")
        result = self.command("doctor", "--json", *(["--worker", worker] if worker else []))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["compile_verified"])
        self.assertFalse(report["capabilities"]["requires_hol_services"])
        self.assertLessEqual(report["rendered_tokens"], 256)

    def test_example_and_cli_exercise_reviewed_release_abstention_and_refresh(self):
        worker = os.environ.get("CIGAR_TEST_WORKER")
        self.assertTrue(get_local_context_capabilities(worker_path=worker)["worker_available"])
        report = run_local_workflow(worker_path=worker)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["reviewer"], "scripted-fixture")
        self.assertIn("confident-error-abstention", report["checks"])
        self.assertIn("stale-review-rejection", report["checks"])
        self.assertNotEqual(report["released_claims"], report["refreshed_claims"])
        result = self.command("demo", "--json", *(["--worker", worker] if worker else []))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), report)
