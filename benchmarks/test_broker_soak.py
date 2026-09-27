"""The soak evidence must reject partial time, missing events and failed clients."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from broker_soak import Journal, check_cycle, configuration, replay
from broker_storage import encoded


def check():
    return {
        "name": "fixture-check",
        "expected": {"status": "ok"},
        "observed": {"status": "ok"},
        "passed": True,
    }


def cycle():
    operation = {"status": "ok", "elapsed_ms": 1, "timing": None}
    return {
        "status": "ok",
        "compile": operation,
        "forget": operation,
        "rendered_sha256": "1" * 64,
    }


def transcript():
    config = configuration(60)
    rows = [
        {
            "kind": "start",
            "elapsed_seconds": 0,
            "actor_pids": list(range(1, 13)),
            "initial_checks": [check()],
        }
    ]
    for tick in range(1, 60):
        rows.append(
            {
                "kind": "cycle",
                "elapsed_seconds": tick,
                "observations": [cycle() for _ in range(12)],
                "rss_bytes": [1] * 14,
            }
        )
        offset = 0
        for phase, period in config["periods_seconds"].items():
            if tick % period == 0:
                offset += 0.02
                rows.extend(
                    [
                        {
                            "kind": "maintenance-start",
                            "phase": phase,
                            "number": tick // period,
                            "elapsed_seconds": tick + offset,
                        },
                        {
                            "kind": "maintenance-end",
                            "phase": phase,
                            "number": tick // period,
                            "elapsed_seconds": tick + offset + 0.01,
                            "duration_seconds": 0.01,
                            "checks": [check()],
                        },
                    ]
                )
    rows.extend(
        [
            {"kind": "duration-complete", "elapsed_seconds": 60},
            {
                "kind": "final-verification",
                "elapsed_seconds": 60.1,
                "checks": [check()],
            },
        ]
    )
    return rows


class SoakEvidenceTests(unittest.TestCase):
    def replay_rows(self, rows):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            payload = b"".join(
                encoded({"sequence": i, **row}) for i, row in enumerate(rows)
            )
            (directory / "observations.jsonl").write_bytes(payload)
            result = replay(directory, {"configuration": configuration(60)})
            self.assertEqual(
                result["observations_sha256"], hashlib.sha256(payload).hexdigest()
            )
            return result

    def test_smoke_duration_never_becomes_a_day(self):
        self.assertEqual(configuration(60)["mode"], "smoke-only")
        self.assertEqual(configuration(86399)["mode"], "smoke-only")
        self.assertEqual(configuration(86400)["mode"], "24-hour-soak")
        for invalid in (0, 59, 86401, 86400.0, True):
            with self.assertRaises(ValueError):
                configuration(invalid)
        result = self.replay_rows(transcript())
        self.assertEqual(result["cycles_per_actor"], 59)
        self.assertEqual(result["total_cycles"], 708)
        self.assertEqual(result["maintenance"]["restart"], 1)

    def test_partial_or_missing_final_observation_is_not_complete(self):
        for rows in (transcript()[:-1], transcript()[:-2]):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                self.replay_rows(rows)
        rows = transcript()
        rows[-2]["elapsed_seconds"] = 59.9
        with self.assertRaisesRegex(ValueError, "incomplete soak duration"):
            self.replay_rows(rows)

    def test_missing_restart_or_unexplained_gap_fails(self):
        rows = [row for row in transcript() if row.get("phase") != "restart"]
        with self.assertRaisesRegex(ValueError, "missing maintenance"):
            self.replay_rows(rows)
        rows = transcript()
        rows[1]["elapsed_seconds"] = 6
        with self.assertRaisesRegex(ValueError, "observation gap"):
            self.replay_rows(rows)

    def test_failed_operation_and_forged_maintenance_success_fail(self):
        value = cycle()
        value["compile"] = {
            "status": "error",
            "code": "Timeout",
            "dispatched": None,
            "elapsed_ms": 5000,
            "timing": None,
        }
        with self.assertRaisesRegex(ValueError, "operation failure"):
            check_cycle(value)
        rows = transcript()
        event = next(row for row in rows if row["kind"] == "maintenance-end")
        event["checks"][0]["observed"]["status"] = "error"
        with self.assertRaisesRegex(ValueError, "maintenance check"):
            self.replay_rows(rows)

    def test_unpaired_or_reordered_maintenance_fails(self):
        rows = transcript()
        next(row for row in rows if row["kind"] == "maintenance-end")["number"] += 1
        with self.assertRaisesRegex(ValueError, "unpaired maintenance"):
            self.replay_rows(rows)

    def test_journal_is_bounded_private_and_cannot_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observations.jsonl"
            journal = Journal(path, 100)
            try:
                for secret in ("connection", "secret", "private_ticket"):
                    with self.assertRaises(ValueError):
                        journal.append({"nested": [{secret: "fixture"}]})
                self.assertEqual(journal.count, 0)
                journal.append({"status": "ok"})
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, "bound"):
                    journal.append({"oversized": "x" * 101})
                self.assertEqual(path.read_bytes(), before)
            finally:
                journal.close()
            with self.assertRaises(FileExistsError):
                Journal(path, 100)


if __name__ == "__main__":
    unittest.main()
