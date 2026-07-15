#!/usr/bin/env python3
from __future__ import annotations

import sys
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from release_lib import (  # noqa: E402
    ReleaseError,
    child_environment_without_evidence,
    reject_evidence_directory,
    run_bounded,
    scan_payload,
    selected_evidence_directory,
    validate_content_scan_exemptions,
)


class BoundedProcessTests(unittest.TestCase):
    def test_bounded_input_is_delivered_without_pipe_deadlock(self) -> None:
        payload = b"reviewed-input" * 4096
        result = run_bounded(
            [
                sys.executable,
                "-c",
                "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
            ],
            input_payload=payload,
            max_stdin=len(payload),
            max_stdout=128,
            max_stderr=128,
        )
        import hashlib

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout.strip().decode("ascii"), hashlib.sha256(payload).hexdigest()
        )

    def test_output_overflow_kills_the_process_and_fails_closed(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "output limit exceeded"):
            run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'x' * 1048576)",
                ],
                input_payload=b"input",
                max_stdout=1024,
                max_stderr=128,
            )

    def test_input_limit_is_checked_before_process_creation(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "limits are invalid"):
            run_bounded(
                [sys.executable, "-c", "raise SystemExit(99)"],
                input_payload=b"too-large",
                max_stdin=1,
            )

    @unittest.skipUnless(os.name == "posix", "process-group assertion is POSIX-only")
    def test_timeout_kills_process_group_descendants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cigar-bounded-process-") as raw:
            marker = Path(raw) / "escaped-child-ran"
            child = (
                "import pathlib,time; "
                "time.sleep(1.5); "
                f"pathlib.Path({os.fspath(marker)!r}).write_bytes(b'escaped')"
            )
            parent = (
                "import subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}]); "
                "print(child.pid,flush=True); "
                "time.sleep(30)"
            )
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                run_bounded(
                    [sys.executable, "-c", parent],
                    timeout=0.5,
                    max_stdout=128,
                    max_stderr=128,
                )
            self.assertRegex((raised.exception.stdout or b"").strip(), rb"^[0-9]+$")
            time.sleep(1.25)
            self.assertFalse(marker.exists())


class EvidenceSelectorTests(unittest.TestCase):
    def test_exactly_one_absolute_selector_is_accepted(self) -> None:
        selected = selected_evidence_directory(
            Path("/tmp/cigar-evidence"),
            environment={"CIGAR_EVIDENCE_DIR": "/tmp/cigar-evidence"},
        )
        self.assertEqual(selected, Path("/tmp/cigar-evidence"))
        self.assertEqual(
            selected_evidence_directory(
                None,
                environment={"CIGAR_EVIDENCE_DIR": "/tmp/from-environment"},
            ),
            Path("/tmp/from-environment"),
        )

    def test_conflict_and_relative_selector_fail_closed(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "conflicts"):
            selected_evidence_directory(
                Path("/tmp/argument"),
                environment={"CIGAR_EVIDENCE_DIR": "/tmp/environment"},
            )
        with self.assertRaisesRegex(ReleaseError, "absolute"):
            selected_evidence_directory(
                Path("relative/output"),
                environment={},
            )

    def test_inapplicable_and_child_selector_are_explicit(self) -> None:
        with self.assertRaisesRegex(ReleaseError, "inapplicable"):
            reject_evidence_directory(
                None,
                "source mutation",
                environment={"CIGAR_EVIDENCE_DIR": "/tmp/evidence"},
            )
        child = child_environment_without_evidence(
            {"CIGAR_EVIDENCE_DIR": "/tmp/evidence", "KEEP": "yes"}
        )
        self.assertEqual(child, {"KEEP": "yes"})


class ContentScanExemptionTests(unittest.TestCase):
    def test_finding_scoped_exemption_keeps_other_detectors_enabled(self) -> None:
        exemptions = validate_content_scan_exemptions(
            [
                {
                    "pattern": "fixtures/*.json",
                    "reason": "synthetic legacy path",
                    "findings": ["macos-developer-path"],
                }
            ]
        )
        payload = b"/Users/" + b"example/project\n-----BEGIN " + b"PRIVATE KEY-----\n"
        self.assertEqual(
            scan_payload("fixtures/state.json", payload, exemptions),
            ["private-key"],
        )

    def test_unknown_or_empty_finding_scope_is_rejected(self) -> None:
        for findings in ([], ["unknown-finding"]):
            with self.subTest(findings=findings):
                with self.assertRaisesRegex(ReleaseError, "exemptions are invalid"):
                    validate_content_scan_exemptions(
                        [
                            {
                                "pattern": "fixture",
                                "reason": "synthetic fixture",
                                "findings": findings,
                            }
                        ]
                    )


if __name__ == "__main__":
    unittest.main()
