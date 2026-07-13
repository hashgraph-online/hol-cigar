#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from release_lib import ReleaseError, run_bounded  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
