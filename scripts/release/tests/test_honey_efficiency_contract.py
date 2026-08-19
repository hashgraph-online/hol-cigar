from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = ROOT / "scripts" / "release"
sys.path.insert(0, str(RELEASE_SCRIPTS))

import honey_efficiency_contract as contract  # noqa: E402
from release_lib import canonical_json_bytes  # noqa: E402


class HoneyEfficiencyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures, cls.fixture_payload = contract.load_json(
            ROOT / contract.FIXTURE_PATH
        )
        cls.profile, cls.profile_payload = contract.load_json(ROOT / contract.PROFILE_PATH)

    def report(self, raw: bytes) -> dict[str, object]:
        fixture_entries = [
            {
                "id": row["id"],
                "sha256": row["fixture_sha256"],
                "kind": "generated",
            }
            for row in self.fixtures["fixtures"]
        ]
        gates = []
        for row in self.profile["required_gates"]:
            thresholds = []
            measurements = []
            for name, operator, value, unit in contract.EXPECTED_GATE_THRESHOLDS[
                row["id"]
            ]:
                if operator == "lt":
                    observed = value - 1
                elif operator == "gt":
                    observed = value + 1
                else:
                    observed = value
                thresholds.append(
                    {"name": name, "operator": operator, "value": value, "unit": unit}
                )
                measurements.append({"name": name, "value": observed, "unit": unit})
            gates.append(
                {
                    "gate_id": row["id"],
                    "release_gate_id": row["release_gate_id"],
                    "status": "pass",
                    "thresholds": thresholds,
                    "measurements": measurements,
                    "evidence_sha256": hashlib.sha256(row["id"].encode()).hexdigest(),
                }
            )
        workflows = [
            {
                "id": f"workflow-{index}",
                "requests": 20,
                "completed": 20,
                "selected": 20,
                "duplicate_selected": 0,
                "budget_displaced": 0,
                "citation_total": 20,
                "citation_resolved": 20,
                "required_source_total": 20,
                "required_source_resolved": 20,
                "local_lineages": 20,
                "cigar_lineages": 20,
                "lineage_delta": 0,
                "status": "pass",
            }
            for index in range(1, 6)
        ]
        return {
            "schema_version": contract.REPORT_SCHEMA_VERSION,
            "report_id": "candidate-qualification-001",
            "generated_at": "2026-07-20T12:00:00Z",
            "authorities": {
                "qualification_profile_sha256": contract.PROFILE_SHA256,
                "report_schema_sha256": contract.REPORT_SCHEMA_SHA256,
            },
            "product": {
                "version": "0.9.3",
                "release_state": "developer-preview",
                "context_abi": "cigar.context.v1",
                "target_triple": "aarch64-apple-darwin",
                "prerelease": True,
                "supported": False,
                "production_qualified": False,
            },
            "source": {"commit": "a" * 40, "tree": "b" * 40, "clean": True},
            "candidate": {
                "manifest_sha256": "c" * 64,
                "installed_runtime_sha256": "d" * 64,
            },
            "fixtures": {
                "manifest_sha256": contract.FIXTURE_SHA256,
                "entries": fixture_entries,
            },
            "raw_observations": {
                "attachment_id": "raw-observations",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            },
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
            "stage_metrics": [
                {
                    "id": "repository-load",
                    "samples": 100,
                    "unit": "nanoseconds",
                    "minimum": 1,
                    "maximum": 5,
                    "mean": 3,
                    "p50": 3,
                    "p95": 5,
                }
            ],
            "gate_results": gates,
            "workflows": workflows,
            "overall_status": "pass",
            "fail_closed": True,
        }

    def test_frozen_authorities_and_valid_report_pass(self) -> None:
        bindings = contract.validate_authorities(ROOT)
        self.assertEqual(bindings["fixture_sha256"], contract.FIXTURE_SHA256)
        raw = b'{"observations":[]}\n'
        report = contract.validate_report(self.report(raw), self.fixtures, self.profile)
        with tempfile.TemporaryDirectory() as directory:
            attachment = Path(directory) / "raw.json"
            attachment.write_bytes(raw)
            contract.validate_raw_attachment(report, attachment)

    def test_missing_skipped_or_misstated_gate_fails_closed(self) -> None:
        raw = b"raw\n"
        missing = self.report(raw)
        missing["gate_results"].pop()
        with self.assertRaisesRegex(contract.EfficiencyContractError, "invalid count"):
            contract.validate_report(missing, self.fixtures, self.profile)

        skipped = self.report(raw)
        skipped["gate_results"][0]["status"] = "skipped"
        with self.assertRaisesRegex(contract.EfficiencyContractError, "disagrees"):
            contract.validate_report(skipped, self.fixtures, self.profile)

        misstated = self.report(raw)
        misstated["gate_results"][0]["measurements"][0]["value"] = False
        with self.assertRaisesRegex(contract.EfficiencyContractError, "disagrees"):
            contract.validate_report(misstated, self.fixtures, self.profile)

    def test_raw_attachment_digest_and_size_are_required(self) -> None:
        raw = b"expected\n"
        report = contract.validate_report(self.report(raw), self.fixtures, self.profile)
        with tempfile.TemporaryDirectory() as directory:
            attachment = Path(directory) / "raw.json"
            attachment.write_bytes(b"changed\n")
            with self.assertRaisesRegex(contract.EfficiencyContractError, "binding failed"):
                contract.validate_raw_attachment(report, attachment)

    def test_duplicate_keys_and_nonfinite_numbers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_bytes(b'{"value":1,"value":2}\n')
            with self.assertRaisesRegex(contract.EfficiencyContractError, "duplicate"):
                contract.load_json(path)
            path.write_bytes(b'{"value":NaN}\n')
            with self.assertRaisesRegex(contract.EfficiencyContractError, "non-finite"):
                contract.load_json(path)

    def test_fixture_or_execution_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.fixtures)
        changed["fixtures"][0]["generator_inputs"]["request_count"] = 13
        with self.assertRaisesRegex(contract.EfficiencyContractError, "digest drifted"):
            contract.validate_fixture_manifest(changed, canonical_json_bytes(changed))

        report = self.report(b"raw\n")
        report["execution"]["warmup_requests"] = 4
        with self.assertRaisesRegex(contract.EfficiencyContractError, "execution conditions"):
            contract.validate_report(report, self.fixtures, self.profile)

    def test_historical_handoff_is_external_and_path_free(self) -> None:
        contract.validate_qualification_profile(self.profile, self.profile_payload)
        self.assertEqual(
            self.profile["authenticated_inputs"][1],
            contract.HISTORICAL_HANDOFF_INPUT,
        )
        self.assertNotIn("path", self.profile["authenticated_inputs"][1])

    def test_threshold_weakening_is_rejected(self) -> None:
        report = self.report(b"raw\n")
        report["gate_results"][3]["thresholds"][0]["value"] = 1_048_577
        with self.assertRaisesRegex(contract.EfficiencyContractError, "drifted or weakened"):
            contract.validate_report(report, self.fixtures, self.profile)

    def test_verified_copy_descriptor_has_no_path_or_protected_name(self) -> None:
        bound = {
            "schema_version": contract.VERIFIED_COPY_SCHEMA_VERSION,
            "input_id": contract.VERIFIED_COPY_ID,
            "status": "bound",
            "content_free": True,
            "executable": True,
            "binding": {
                "store_identity_sha256": "1" * 64,
                "store_sha256": "2" * 64,
                "bytes": 1024,
                "source_revision": 1024,
                "copy_receipt_sha256": "3" * 64,
            },
            "required_generated_gates": list(contract.REQUIRED_GENERATED_GATES),
        }
        contract.validate_verified_copy_descriptor(bound)
        bound["binding"]["path"] = "/private/protected.sqlite3"
        with self.assertRaisesRegex(contract.EfficiencyContractError, "fields are not closed"):
            contract.validate_verified_copy_descriptor(bound)


if __name__ == "__main__":
    unittest.main()
