"""Release metadata parsing must not discard or parse tool diagnostics as JSON."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from prepare_context_sdk_rc import run_logged  # noqa: E402


class BuildOutputTests(unittest.TestCase):
    def test_metadata_json_and_warnings_are_retained_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log, stderr = directory / "metadata.log", directory / "metadata.stderr"
            result = run_logged(
                [
                    sys.executable,
                    "-c",
                    'import sys; print("warning: fixture", file=sys.stderr); '
                    "print('{\"packages\": []}')",
                ],
                cwd=directory,
                env=os.environ.copy(),
                log=log,
                stderr=stderr,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(log.read_bytes()), {"packages": []})
            self.assertEqual(stderr.read_text(), "warning: fixture\n")

    def test_failure_status_and_ordinary_combined_log_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / "failed.log"
            result = run_logged(
                [
                    sys.executable,
                    "-c",
                    'import sys; print("output"); '
                    'print("diagnostic", file=sys.stderr); sys.exit(7)',
                ],
                cwd=directory,
                env=os.environ.copy(),
                log=log,
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(
                set(log.read_text().splitlines()), {"output", "diagnostic"}
            )
