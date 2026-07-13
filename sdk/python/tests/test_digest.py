from __future__ import annotations

import json
import unittest
from pathlib import Path

from cigar_sdk import apply_context_delta, bundle_id, delta_digest, verify_bundle


class DigestTests(unittest.TestCase):
    def test_shared_bundle_fixture(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "fixtures/semantic-bundle-v1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        verify_bundle(fixture["bundle"])
        self.assertEqual(bundle_id(fixture["bundle"]), fixture["expected_bundle_id"])

    def test_empty_bundle_delta_is_verified_and_copy_safe(self) -> None:
        fixture_path = Path(__file__).resolve().parents[2] / "fixtures/semantic-bundle-v1.json"
        base = json.loads(fixture_path.read_text(encoding="utf-8"))["bundle"]
        target = dict(base)
        target["contract_digest"] = "1220" + "3" * 64
        target["bundle_id"] = bundle_id(target)
        delta = {
            "schema_version": "cigar.context-delta.v1",
            "base_bundle_id": base["bundle_id"],
            "target_bundle_id": target["bundle_id"],
            "added_blocks": [],
            "removed_block_ids": [],
            "resulting_tokens": 0,
        }
        result = apply_context_delta(base, target, delta, delta_digest(delta))
        self.assertEqual(result, target)
        self.assertIsNot(result, target)


if __name__ == "__main__":
    unittest.main()
