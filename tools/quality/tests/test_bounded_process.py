from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tools.quality import bounded_process


class BoundedProcessTests(unittest.TestCase):
    def run_child(
        self,
        base: Path,
        name: str,
        command: list[str],
        *,
        timeout: float = 2,
        maximum: int = 1024,
    ) -> dict[str, object]:
        return bounded_process.run_bounded(
            command,
            cwd=base,
            env={"PATH": os.environ.get("PATH", "")},
            log_path=base / f"{name}.log",
            timeout_seconds=timeout,
            maximum_output_bytes=maximum,
            tail_bytes=128,
        )

    def test_noisy_child_is_killed_at_exact_private_log_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            result = self.run_child(
                base,
                "noisy",
                [sys.executable, "-c", "import os; os.write(1, b'x' * 8192)"],
            )
            log = base / "noisy.log"
            self.assertTrue(result["output_overflow"])
            self.assertEqual(result["captured_output_bytes"], 1024)
            self.assertEqual(log.stat().st_size, 1024)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(len(str(result["tail"]).encode()), 128)

    def test_quiet_child_is_killed_at_wall_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            started = time.monotonic()
            result = self.run_child(
                base,
                "timeout",
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=0.2,
            )
            self.assertTrue(result["timed_out"])
            self.assertLess(time.monotonic() - started, 3)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group regression")
    def test_parent_exit_with_background_pipe_holder_times_out_and_kills_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            result = self.run_child(
                base,
                "pipe-holder",
                ["/bin/sh", "-c", "(sleep 30) & exit 0"],
                timeout=0.2,
            )
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["descendant_cleanup_required"])

    @unittest.skipUnless(os.name == "posix", "POSIX process-group regression")
    def test_parent_exit_with_closed_pipe_descendant_is_detected_and_killed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            result = self.run_child(
                base,
                "closed-pipe-holder",
                [
                    "/bin/sh",
                    "-c",
                    "(exec >/dev/null 2>&1; sleep 30) & exit 0",
                ],
                timeout=2,
            )
            self.assertFalse(result["timed_out"])
            self.assertTrue(result["descendant_cleanup_required"])

    def test_unsupported_process_model_fails_closed(self) -> None:
        with self.assertRaises(bounded_process.BoundedProcessError):
            bounded_process.require_supported_process_model(os_name="nt")


if __name__ == "__main__":
    unittest.main()
