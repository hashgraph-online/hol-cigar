from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GUIDE = "docs/guides/honey-0.9.4-upgrade.md"
PROFILE_AUTHORITY_SHA256 = (
    "a899c3312ebdfad8d29ecf7a52c63bf8bd3bcf92ee478d425364aec46bdde94d"
)


def load_json(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{relative} is not an object")
    return value


class Honey094DocumentationSurfaceTests(unittest.TestCase):
    def test_published_docs_and_examples_cover_every_declared_user_surface(
        self,
    ) -> None:
        manifest = load_json("docs/site-manifest.v1.json")
        required = set(manifest["required_pages"])
        self.assertTrue(
            {
                GUIDE,
                "docs/reference/cli.md",
                "docs/reference/configuration-authority.md",
                "docs/reference/policy-capabilities.md",
                "docs/guides/honey-storage-v5.md",
                "docs/runbooks/local-storage-recovery.md",
            }.issubset(required)
        )
        for relative in [
            "crates/cigar-cli/assets/cigar-help.txt",
            "crates/cigar-cli/completions/cigar.bash",
            "crates/cigar-cli/completions/_cigar",
            "crates/cigar-cli/completions/cigar.fish",
            "crates/cigar-cli/man/cigar.1",
            "sdk/rust/examples/quickstart.rs",
            "sdk/python/examples/quickstart.py",
            "sdk/typescript/src/examples/quickstart.ts",
            "sdk/go/examples/quickstart/main.go",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_upgrade_profile_capability_and_rollback_contracts_are_coherent(
        self,
    ) -> None:
        authority_path = ROOT / "spec/configuration/authority-v1.json"
        self.assertEqual(
            hashlib.sha256(authority_path.read_bytes()).hexdigest(),
            PROFILE_AUTHORITY_SHA256,
        )
        authority = load_json("spec/configuration/authority-v1.json")
        setting = next(
            row
            for row in authority["settings"]
            if row["id"] == "daemon.intelligence_profile"
        )
        self.assertEqual(
            setting,
            {
                "id": "daemon.intelligence_profile",
                "owner": "cigar-daemon",
                "profiles": ["embedded", "local_sidecar", "shared_service"],
                "precedence": ["explicit_config"],
                "allowed_sources": ["explicit_config"],
                "default_semantics": "balanced_v3_when_absent",
                "required_semantics": "closed_balanced_v1_balanced_v3_balanced_v4",
                "secret_classification": "non_secret",
                "value_form": "typed_value",
                "provenance_label": "intelligence_profile",
                "project_configuration_forbidden": True,
                "macos_disposition": "active",
            },
        )

        operation = load_json("schemas/openapi/cigar-v1.json")["paths"][
            "/v1/capabilities"
        ]["get"]
        self.assertEqual(operation["operationId"], "getCapabilities")
        self.assertEqual(operation["security"], [])
        self.assertEqual(operation["x-cigar-auth-class"], "anonymous")
        self.assertEqual(operation["x-cigar-response-schema"], "CapabilitiesResponse")

        guide = (ROOT / GUIDE).read_text(encoding="utf-8")
        for required_text in [
            "intelligence-balanced-v4",
            "intelligence-balanced-v3",
            "intelligence-balanced-v1",
            "separately restored rehearsal state",
            "Binary rollback never opens or rewrites the candidate's state with an older runtime",
            "Never downgrade a live state directory",
            "source-tree binary as installed-artifact evidence",
        ]:
            self.assertIn(required_text, guide)


if __name__ == "__main__":
    unittest.main()
