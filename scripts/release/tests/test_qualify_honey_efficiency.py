from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = ROOT / "scripts" / "release"
sys.path.insert(0, str(RELEASE_SCRIPTS))

import honey_efficiency_contract as contract  # noqa: E402
import qualify_honey_efficiency as qualify  # noqa: E402
from release_lib import canonical_json_bytes  # noqa: E402


class HoneyEfficiencyQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures, cls.fixture_payload = contract.load_json(
            ROOT / contract.FIXTURE_PATH
        )
        cls.profile, cls.profile_payload = contract.load_json(ROOT / contract.PROFILE_PATH)

    def raw(self) -> dict[str, object]:
        entries = [
            {"id": row["id"], "sha256": row["fixture_sha256"], "kind": "generated"}
            for row in self.fixtures["fixtures"]
        ]
        workflows = [
            {
                "id": f"workflow-{index}",
                "requests": 20,
                "completed": 20,
                "selected": 20,
                "duplicate_selected": 0,
                "budget_displaced": 10,
                "citation_total": 20,
                "citation_resolved": 20,
                "required_source_total": 20,
                "required_source_resolved": 20,
                "local_lineages": 10,
                "cigar_lineages": 11,
            }
            for index in range(1, 6)
        ]
        return {
            "schema_version": qualify.RAW_SCHEMA_VERSION,
            "run_id": "candidate-qualification-001",
            "generated_at": "2026-07-20T12:00:00Z",
            "source": {"commit": "a" * 40, "tree": "b" * 40, "clean": True},
            "candidate": {
                "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
                "installed_runtime_sha256": hashlib.sha256(b"runtime").hexdigest(),
            },
            "fixtures": {"manifest_sha256": contract.FIXTURE_SHA256, "entries": entries},
            "environment": {
                "host_os": "macos",
                "os_version": "15.6",
                "kernel": "Darwin 24.6.0",
                "architecture": "arm64",
                "cpu_model": "Apple M3 Ultra",
                "filesystem": "apfs",
                "power_source": "ac",
                "low_power_mode": False,
                "thermal_state": "nominal",
                "network_used": False,
                "tools": [
                    {"id": "cargo", "version": "1.92.0"},
                    {"id": "python", "version": "3.14.6"},
                    {"id": "rustc", "version": "1.92.0"},
                    {"id": "sqlite", "version": "3.43.2"},
                ],
            },
            "execution": contract._expected_execution(self.fixtures),
            "stages": [{"id": "context-compile", "observations_ns": [1_000_000] * 100}],
            "latency": {
                "serial_request_latencies_ns": [1_000_000_000] * 100,
                "compile_latencies_ns": [1_000_000_000] * 100,
                "paired_local_compile_latencies_ns": [1_000_000_000] * 100,
                "bootstrap_seed": "1" * 64,
                "bootstrap_repetitions": 10_000,
                "bootstrap_block_length": 10,
            },
            "storage": {
                "incremental_storage_format": True,
                "migration_root_revision_exact": True,
                "failpoint_recovery_exact": True,
                "physical_initial_bytes": 1_000_000,
                "physical_final_bytes": 1_000_100,
                "completed_compilations": 100,
                "serial_mutations_completed": 10_000,
                "retained_checkpoints": 39,
                "retained_deltas": 9_962,
                "readiness_suffix_deltas": 15,
                "readiness_suffix_bytes": 1_000_000,
                "mixed_workers_completed": 4,
                "mixed_mutations_per_worker_completed": 2_500,
                "backup_restore_downgrade_passed": True,
                "compaction_pin_drift_passed": True,
                "deep_integrity_passed": True,
            },
            "startup": {
                "clean_readiness_ns": 8_000_000,
                "crash_recovery_readiness_ns": 16_000_000,
            },
            "workflows": workflows,
            "validation": {
                "required": True,
                "policy": True,
                "security": True,
                "provenance": True,
                "tokenizer": True,
                "materializer": True,
                "budget": True,
            },
            "compatibility": {
                "v1_operation_count": 45,
                "v1_nominal_payload_count": 70,
                "granular_v1_clients_compatible": True,
                "future_operations_added_to_v1": False,
                "legacy_mandatory_gates_passed": True,
            },
        }

    def test_valid_raw_builds_one_closed_passing_report(self) -> None:
        raw = qualify.validate_raw_observations(self.raw())
        payload = canonical_json_bytes(raw)
        report = qualify.build_report(raw, payload, self.profile)
        self.assertEqual(report["overall_status"], "pass")
        contract.validate_report(report, self.fixtures, self.profile)
        self.assertEqual(len(report["gate_results"]), 23)
        self.assertEqual(len(report["workflows"]), 5)

    def test_bootstrap_is_deterministic_and_detects_progressive_latency(self) -> None:
        flat = [1_000_000_000] * 100
        first = qualify.moving_block_bootstrap_interval(
            flat, seed="2" * 64, repetitions=10_000, block_length=10
        )
        second = qualify.moving_block_bootstrap_interval(
            flat, seed="2" * 64, repetitions=10_000, block_length=10
        )
        self.assertEqual(first, (0, 0))
        self.assertEqual(first, second)
        slope = qualify._ceil_fraction(
            qualify._ols_slope([index * 11_000_000 + 1 for index in range(100)])
        )
        self.assertEqual(slope, 11_000_000)

    def test_empty_or_incomplete_cohorts_are_rejected(self) -> None:
        raw = self.raw()
        raw["storage"]["completed_compilations"] = 0
        with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "empty"):
            qualify.validate_raw_observations(raw)
        raw = self.raw()
        raw["latency"]["serial_request_latencies_ns"].pop()
        with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "invalid count"):
            qualify.validate_raw_observations(raw)
        raw = self.raw()
        raw["storage"]["mixed_workers_completed"] = 3
        with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "incomplete"):
            qualify.validate_raw_observations(raw)

    def test_threshold_weakening_is_rejected_after_production(self) -> None:
        raw = qualify.validate_raw_observations(self.raw())
        report = qualify.build_report(raw, canonical_json_bytes(raw), self.profile)
        report["gate_results"][4]["thresholds"][0]["value"] = 11_000_000
        with self.assertRaisesRegex(contract.EfficiencyContractError, "drifted or weakened"):
            contract.validate_report(report, self.fixtures, self.profile)

    def test_duplicate_and_nonfinite_raw_json_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.json"
            path.write_bytes(b'{"value":1,"value":2}\n')
            with self.assertRaisesRegex(contract.EfficiencyContractError, "duplicate"):
                contract.load_json(path)
            path.write_bytes(b'{"value":Infinity}\n')
            with self.assertRaisesRegex(contract.EfficiencyContractError, "non-finite"):
                contract.load_json(path)

    def test_missing_relative_and_symlink_inputs_are_rejected(self) -> None:
        with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "absolute"):
            qualify._regular_file_payload(Path("missing.json"), "raw", 1024)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target.json"
            target.write_bytes(b"{}")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                qualify.EfficiencyQualificationError, "canonical regular"
            ):
                qualify._regular_file_payload(link, "raw", 1024)

    def test_stale_candidate_and_source_bindings_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            raw_document = self.raw()
            raw_path = scratch / "raw.json"
            manifest = scratch / "manifest.json"
            runtime = scratch / "runtime"
            manifest.write_bytes(b"changed")
            runtime.write_bytes(b"runtime")
            raw_path.write_bytes(canonical_json_bytes(raw_document))
            with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "manifest"):
                qualify.produce(
                    root=ROOT,
                    raw_path=raw_path,
                    candidate_manifest_path=manifest,
                    installed_runtime_path=runtime,
                    output=scratch / "stale-candidate-output",
                )

            manifest.write_bytes(b"manifest")
            with mock.patch.object(
                qualify, "_git_identity", return_value=("c" * 40, "d" * 40)
            ):
                with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "source"):
                    qualify.produce(
                        root=ROOT,
                        raw_path=raw_path,
                        candidate_manifest_path=manifest,
                        installed_runtime_path=runtime,
                        output=scratch / "stale-source-output",
                    )

    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "existing"
            output.mkdir()
            marker = output / "marker"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(qualify.EfficiencyQualificationError, "already exists"):
                qualify.produce(
                    root=ROOT,
                    raw_path=Path("missing"),
                    candidate_manifest_path=Path("missing"),
                    installed_runtime_path=Path("missing"),
                    output=output,
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_producer_creates_private_report_bound_to_external_raw_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            raw_document = self.raw()
            raw_path = scratch / "raw.json"
            manifest = scratch / "manifest.json"
            runtime = scratch / "runtime"
            output = scratch / "qualification"
            raw_path.write_bytes(canonical_json_bytes(raw_document))
            manifest.write_bytes(b"manifest")
            runtime.write_bytes(b"runtime")
            with mock.patch.object(
                qualify, "_git_identity", return_value=("a" * 40, "b" * 40)
            ):
                report = qualify.produce(
                    root=ROOT,
                    raw_path=raw_path,
                    candidate_manifest_path=manifest,
                    installed_runtime_path=runtime,
                    output=output,
                )
            self.assertEqual(report["overall_status"], "pass")
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / qualify.REPORT_NAME).stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                {path.name for path in output.iterdir()}, {qualify.REPORT_NAME}
            )
            contract.validate_raw_attachment(report, raw_path)


if __name__ == "__main__":
    unittest.main()
