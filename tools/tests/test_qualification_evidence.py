from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
RELEASE = ROOT / "scripts" / "release"
for entry in (str(TOOLS), str(RELEASE)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import qualification_evidence as evidence  # noqa: E402
from evidence_workspace import (  # noqa: E402
    EvidenceWorkspaceError,
    canonical_json_bytes,
)


PASS_STATE = {
    "schema_version": "cigar.shared-qualification.v1",
    "packet": "WP18",
    "result": "pass",
    "postgres_dump_restore": True,
    "postgres_basebackup_manifest_verified": True,
    "postgres_private_ca_tls": True,
    "s3_compatible_live": True,
    "s3_fresh_namespace_restore": True,
    "s3_runtime_immutable_delete_denied": True,
    "deployment_assets": True,
}


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-qualification-evidence-test-", dir="/private/tmp"
        )
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        (self.repository / "tools").mkdir()
        self.script = self.repository / "tools" / "worker.sh"
        self.profile = evidence.Profile(
            identifier="shared-profile",
            script="tools/worker.sh",
            schema_version="cigar.shared-qualification.v1",
            receipt_path="receipt.json",
            log_path="qualification.log",
        )
        self._write_worker(self._pass_worker())
        self._git("init", "--quiet")
        self._git("config", "user.name", "CIGAR Test")
        self._git("config", "user.email", "cigar-test@example.invalid")
        self._git("add", "tools/worker.sh")
        self._git("commit", "--quiet", "-m", "test fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=self.repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def _write_worker(self, body: str) -> None:
        self.script.write_text(body, encoding="utf-8")
        self.script.chmod(0o700)

    def _pass_worker(self, prefix: str = "") -> str:
        state = json.dumps(PASS_STATE, separators=(",", ":"), sort_keys=True)
        return f"""#!/bin/bash
set -euo pipefail
{prefix}
if [[ -n "${{CIGAR_EVIDENCE_DIR+x}}" ]]; then
  printf 'selector leaked to worker\\n' >&2
  exit 89
fi
printf 'worker output\\n'
printf '%s\\n' '{state}' >&"$CIGAR_QUALIFICATION_STATE_FD"
"""

    def _evidence_root(self, name: str = "evidence") -> Path:
        return self.base / name

    def _run(self, evidence_root: Path) -> tuple[int, bytes]:
        output = io.BytesIO()
        result = evidence.run_qualification(
            root=self.repository,
            evidence_root=evidence_root,
            profile=self.profile,
            output=output,
        )
        return result, output.getvalue()

    def test_pass_publishes_only_two_read_only_bound_files(self) -> None:
        evidence_root = self._evidence_root()
        result, output = self._run(evidence_root)
        self.assertEqual(result, 0)
        self.assertIn(b"worker output", output)
        self.assertEqual(
            sorted(path.name for path in evidence_root.iterdir()),
            ["qualification.log", "receipt.json"],
        )
        for path in evidence_root.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertFalse(path.is_symlink())
        log = (evidence_root / "qualification.log").read_bytes()
        receipt_payload = (evidence_root / "receipt.json").read_bytes()
        receipt = json.loads(receipt_payload)
        self.assertEqual(receipt_payload, canonical_json_bytes(receipt))
        self.assertEqual(receipt["result"], "pass")
        self.assertTrue(receipt["passed"])
        self.assertTrue(receipt["source_stable"])
        self.assertEqual(receipt["source"], receipt["source_after"])
        self.assertFalse(receipt["evidence_selector_forwarded"])
        self.assertEqual(receipt["log"]["bytes"], len(log))
        self.assertEqual(receipt["log"]["sha256"], hashlib.sha256(log).hexdigest())

    def test_source_mutation_forces_a_failing_receipt_and_exit(self) -> None:
        self._write_worker(
            self._pass_worker("printf 'mutated\\n' > mutation-created-by-worker.txt")
        )
        self._git("add", "tools/worker.sh")
        self._git("commit", "--quiet", "-m", "mutating worker")
        evidence_root = self._evidence_root()
        result, _ = self._run(evidence_root)
        self.assertEqual(result, 1)
        receipt = json.loads((evidence_root / "receipt.json").read_bytes())
        self.assertEqual(receipt["result"], "fail")
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["source_stable"])
        self.assertNotEqual(receipt["source"], receipt["source_after"])

    def test_duplicate_worker_json_key_cannot_publish_a_pass(self) -> None:
        duplicate = (
            '{"schema_version":"cigar.shared-qualification.v1",'
            '"packet":"WP18","result":"pass","result":"pass"}'
        )
        self._write_worker(
            f"""#!/bin/bash
set -euo pipefail
printf '%s\\n' '{duplicate}' >&"$CIGAR_QUALIFICATION_STATE_FD"
"""
        )
        self._git("add", "tools/worker.sh")
        self._git("commit", "--quiet", "-m", "duplicate state")
        evidence_root = self._evidence_root()
        result, _ = self._run(evidence_root)
        self.assertEqual(result, 1)
        receipt = json.loads((evidence_root / "receipt.json").read_bytes())
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["worker_report_valid"])

    def test_nonempty_workspace_is_rejected_before_worker_runs(self) -> None:
        evidence_root = self._evidence_root()
        evidence_root.mkdir(mode=0o700)
        collision = evidence_root / "existing"
        collision.write_bytes(b"occupied")
        collision.chmod(0o400)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "inventory mismatch"):
            self._run(evidence_root)

    def test_existing_workspace_requires_exact_owner_private_mode(self) -> None:
        evidence_root = self._evidence_root()
        evidence_root.mkdir(mode=0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self._run(evidence_root)

    def test_relative_inside_and_symlink_roots_are_rejected(self) -> None:
        with self.assertRaises(EvidenceWorkspaceError):
            self._run(Path("relative-evidence"))
        inside = self.repository / "evidence"
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self._run(inside)
        real = self._evidence_root("real-evidence")
        real.mkdir(mode=0o700)
        link = self._evidence_root("linked-evidence")
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self._run(link)

    def test_rebound_workspace_path_is_rejected_without_writing_replacement(
        self,
    ) -> None:
        evidence_root = self._evidence_root()
        prefix = """mv "$REBOUND_EVIDENCE" "$REBOUND_EVIDENCE.original"
mkdir -m 700 "$REBOUND_EVIDENCE"""
        self._write_worker(self._pass_worker(prefix))
        self._git("add", "tools/worker.sh")
        self._git("commit", "--quiet", "-m", "rebound worker")
        with mock.patch.dict(
            os.environ, {"REBOUND_EVIDENCE": str(evidence_root)}, clear=False
        ):
            with self.assertRaisesRegex(
                EvidenceWorkspaceError, "no longer names|does not exist"
            ):
                self._run(evidence_root)
        if evidence_root.exists():
            self.assertEqual(list(evidence_root.iterdir()), [])
        original = Path(f"{evidence_root}.original")
        self.assertTrue(original.is_dir())
        self.assertEqual(list(original.iterdir()), [])


class QualificationDriverDescriptorIsolationTests(unittest.TestCase):
    def test_every_driver_closes_reserved_fd_at_external_and_cleanup_boundaries(
        self,
    ) -> None:
        drivers = (
            ROOT / "tools/qualify-shared-profile.sh",
            ROOT / "tools/qualify-shared-scale.sh",
            ROOT / "tools/wp18-failover/qualify.sh",
        )
        for driver in drivers:
            source = driver.read_text(encoding="utf-8")
            self.assertIn('[[ "$QUALIFICATION_STATE_FD" == 198 ]]', source)
            self.assertIn('-u CIGAR_QUALIFICATION_STATE_FD "$@" 198>&-', source)
            self.assertIn("external docker", source)
            self.assertIn("external rm", source)
        failover = drivers[2].read_text(encoding="utf-8")
        self.assertIn("cargo test --locked --package cigar-store", failover)
        self.assertIn("198>&-", failover)
        self.assertIn("sanitize_output 198>&-", failover)

    def test_shared_worker_children_cannot_read_or_write_terminal_state_fd(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="cigar-qualification-fd-test-", dir="/private/tmp"
        ) as temporary_text:
            temporary = Path(temporary_text)
            stubs = temporary / "bin"
            stubs.mkdir(mode=0o700)
            trace = temporary / "trace.log"
            probe = """#!/usr/bin/python3
import errno
import os
import pathlib
import sys

state_fd = int(os.environ["EXPECTED_CLOSED_STATE_FD"])
for operation in (
    lambda: os.fstat(state_fd),
    lambda: os.write(state_fd, b"forged-worker-state\\n"),
):
    try:
        operation()
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise SystemExit("qualification state descriptor leaked to external child")
for forbidden in (
    "CIGAR_EVIDENCE_DIR",
    "CIGAR_QUALIFICATION_INTERNAL_PROFILE",
    "CIGAR_QUALIFICATION_STATE_FD",
):
    if forbidden in os.environ:
        raise SystemExit(f"{forbidden} leaked to external child")
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["FD_PROBE_TRACE"], "a", encoding="utf-8") as handle:
    handle.write(name + "\\n")
if name == "docker":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "cp":
        destination = pathlib.Path(arguments[-1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("qualification-ca\\n", encoding="utf-8")
    elif "ps" in arguments and arguments[-2:] == ["-q", "postgres"]:
        print("stub-postgres-container")
"""
            for command in ("cargo", "docker", "kubectl"):
                path = stubs / command
                path.write_text(probe, encoding="utf-8")
                path.chmod(0o700)
            state = temporary / "state.json"
            state_fd = os.open(
                state,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "CIGAR_EVIDENCE_DIR": "/must-not-leak",
                    "CIGAR_QUALIFICATION_INTERNAL_PROFILE": "shared-profile",
                    "CIGAR_QUALIFICATION_STATE_FD": "198",
                    "EXPECTED_CLOSED_STATE_FD": "198",
                    "FD_PROBE_TRACE": str(trace),
                    "PATH": f"{stubs}:/usr/bin:/bin:/usr/sbin:/sbin",
                }
            )
            if state_fd != 198:
                os.dup2(state_fd, 198, inheritable=True)
            else:
                os.set_inheritable(198, True)
            try:
                completed = subprocess.run(
                    ["/bin/bash", str(ROOT / "tools/qualify-shared-profile.sh")],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(198,),
                    check=False,
                    timeout=30,
                )
            finally:
                os.close(198)
                if state_fd != 198:
                    os.close(state_fd)
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            document = json.loads(state.read_bytes())
            self.assertEqual(document["result"], "pass")
            self.assertTrue(document["deployment_assets"])
            observed = trace.read_text(encoding="utf-8").splitlines()
            self.assertTrue({"cargo", "docker", "kubectl"}.issubset(observed))


if __name__ == "__main__":
    unittest.main()
