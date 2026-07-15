from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / ".gitleaks.toml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"


class GitleaksPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))

    def allowlist(self, description_prefix: str) -> dict[str, object]:
        matches = [
            item
            for item in self.policy["allowlists"]
            if item["description"].startswith(description_prefix)
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_default_rules_remain_enabled_and_exclusions_are_bounded(self) -> None:
        self.assertEqual(self.policy["extend"], {"useDefault": True})
        for item in self.policy["allowlists"]:
            for path in item.get("paths", []):
                self.assertNotEqual(path, ".*")
                self.assertTrue(path.startswith("^") or "(^|/)" in path)
            for regex in item.get("regexes", []):
                self.assertNotEqual(regex, ".*")
        output_paths = [
            re.compile(expression)
            for expression in self.allowlist(
                "Ignore non-source build, dependency, coverage, and ephemeral test outputs"
            )["paths"]
        ]
        self.assertTrue(
            any(
                expression.search("module/__pycache__/test.pyc")
                for expression in output_paths
            )
        )
        self.assertFalse(
            any(
                expression.search("module/source/test.py")
                for expression in output_paths
            )
        )

    def test_tokenizer_exception_is_match_scoped_and_cannot_hide_other_keys(
        self,
    ) -> None:
        item = self.allowlist("Schema-validated CIGARBench tokenizer identities")
        self.assertEqual(item["targetRules"], ["generic-api-key"])
        self.assertEqual(item["condition"], "AND")
        self.assertEqual(item["regexTarget"], "match")
        expression = re.compile(item["regexes"][0])
        self.assertIsNotNone(
            expression.fullmatch('tokenizer": "cigar-byte-v1:sha256-deadbeef"')
        )
        self.assertIsNone(
            expression.fullmatch('authorization": "cigar-byte-v1:sha256-deadbeef"')
        )
        self.assertIsNone(expression.fullmatch('tokenizer": "unterminated'))

    def test_canary_exception_is_one_fixed_test_value_and_the_leak_test_remains(
        self,
    ) -> None:
        item = self.allowlist("The benchmark test's fixed canary")
        self.assertEqual(
            item["paths"], [r"^benches/cigarbench/tests/test_cigarbench\.py$"]
        )
        expression = re.compile(item["regexes"][0])
        canary = "".join(("BENCH_CANARY_", "POLICY_C28617"))
        self.assertIsNotNone(expression.fullmatch(f'secret = "{canary}"'))
        self.assertIsNone(expression.fullmatch('secret = "production-credential"'))
        source = (ROOT / "benches/cigarbench/tests/test_cigarbench.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("BENCH_CANARY_POLICY_C28617", source)
        self.assertIn("leaking_consumer", source)
        self.assertIn("assertRaises(cigarbench.BenchError)", source)

    def test_requirement_exception_matches_only_the_two_public_test_ids(self) -> None:
        item = self.allowlist("These two integration requirement identifiers")
        self.assertEqual(item["paths"], [r"^tests/integration/matrix-v1\.json$"])
        expression = re.compile(item["regexes"][0])
        authorization_requirement = "".join(("HANDOFF-", "AUTH-001"))
        result_requirement = "".join(("HANDOFF-", "RESULT-001"))
        self.assertIsNotNone(
            expression.fullmatch(f'{authorization_requirement}", "{result_requirement}')
        )
        self.assertIsNone(
            expression.fullmatch(f'{authorization_requirement}", "unexpected-secret"')
        )

    def test_go_demo_vulnerability_scan_cannot_inherit_the_parent_workspace(
        self,
    ) -> None:
        workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            '(cd sdk/go && "$(go env GOPATH)/bin/govulncheck" ./...)', workflow
        )
        self.assertIn(
            "(cd demos/sdk-clients/go-workflow && env GOWORK=off "
            '"$(go env GOPATH)/bin/govulncheck" ./...)',
            workflow,
        )
        self.assertNotIn(
            "(cd demos/sdk-clients/go-workflow && "
            '"$(go env GOPATH)/bin/govulncheck" ./...)',
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
