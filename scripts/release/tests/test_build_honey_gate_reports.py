from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/release"))

import build_honey_gate_reports as gates  # noqa: E402
from release_lib import canonical_json_bytes, sha256_bytes  # noqa: E402


class HoneyGateReportTests(unittest.TestCase):
    def test_bounded_check_inventory_is_closed_and_ordered(self) -> None:
        self.assertEqual(
            [identifier for identifier, _commands in gates.CHECKS],
            [
                "cargo-fmt",
                "cargo-clippy",
                "focused-tests",
                "protocol-parity",
                "canonical-schema-vectors",
                "two-agent-acceptance-reauthorization",
                "policy-denied-nondisclosure",
                "effect-pre-intent-unreachable",
                "effect-unknown-no-blind-retry",
                "effect-duplicate-delivery",
                "malformed-api-mcp",
                "package-negative-verification",
                "local-admin-loopback-default",
                "demos-observational-no-egress",
            ],
        )
        self.assertTrue(
            all(
                command
                for _identifier, commands in gates.CHECKS
                for command in commands
            )
        )

    def test_suppression_requires_exact_path_finding_and_authority(self) -> None:
        exemptions = [
            {
                "pattern": "fixtures/**",
                "reason": "audited fixture",
                "findings": ["private-key"],
            }
        ]
        self.assertEqual(
            gates._suppression("fixtures/key.txt", "private-key", exemptions),
            {
                "path": "fixtures/key.txt",
                "finding": "private-key",
                "authority_pattern": "fixtures/**",
                "authority_reason": "audited fixture",
            },
        )
        self.assertIsNone(
            gates._suppression("fixtures/key.txt", "github-token", exemptions)
        )
        self.assertIsNone(gates._suppression("src/key.txt", "private-key", exemptions))

    def test_report_binds_real_producer_and_keeps_claims_bounded(self) -> None:
        report = gates._report(
            "bounded-safety",
            {
                "revision": "a" * 40,
                "tree": "b" * 40,
                "committed": True,
                "clean": True,
            },
            [
                {
                    "id": "source",
                    "filename": "source.tar.gz",
                    "sha256": "c" * 64,
                    "bytes": 1,
                }
            ],
            {"checks": [], "failed_checks": 0},
            None,
            ROOT,
        )
        self.assertEqual(report["schema_version"], gates.REPORT_SCHEMA)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["producer"]["path"], gates.PRODUCER_PATH)
        self.assertEqual(len(report["producer"]["sha256"]), 64)
        self.assertNotIn("qualified", report)
        self.assertNotIn("supported", report)

    def test_receipt_must_be_canonical_and_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "receipt.json"
            receipt = {
                "schema_version": "fixture.receipt.v1",
                "status": "built-unqualified",
            }
            payload = canonical_json_bytes(receipt)
            path.write_bytes(payload)
            self.assertEqual(
                gates._receipt(path, "fixture.receipt.v1", {"built-unqualified"}),
                receipt,
            )
            reference = {
                "sha256": sha256_bytes(payload),
                "bytes": len(payload),
            }
            manifest = {
                "artifacts": [{"id": "typescript-sdk", "producer_receipt": reference}]
            }
            gates._receipt_binding(manifest, {"typescript-sdk"}, path)
            manifest["artifacts"][0]["producer_receipt"] = {
                **reference,
                "sha256": "0" * 64,
            }
            with self.assertRaisesRegex(gates.HoneyGateReportError, "not bound"):
                gates._receipt_binding(manifest, {"typescript-sdk"}, path)

            path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(gates.HoneyGateReportError, "malformed"):
                gates._receipt(path, "fixture.receipt.v1", {"built-unqualified"})


if __name__ == "__main__":
    unittest.main()
