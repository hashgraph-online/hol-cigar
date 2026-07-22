import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "pypi-honey.yml"
REQUIREMENTS = ROOT / "packaging" / "honey" / "release-requirements.v1.json"


class PyPIHoneyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = WORKFLOW.read_text(encoding="utf-8")

    def test_publication_is_manual_tag_bound_and_approval_gated(self) -> None:
        self.assertIn("workflow_dispatch:", self.document)
        self.assertNotIn("pull_request:", self.document)
        self.assertNotIn("push:\n", self.document)
        self.assertIn(
            'test "${GITHUB_REF}" = "refs/tags/v0.9.1-honey.1"', self.document
        )
        self.assertIn(
            'test "${CONFIRM}" = "publish hol-cigar 0.9.1.dev1"', self.document
        )
        self.assertIn("environment:\n      name: pypi", self.document)

    def test_exact_release_bytes_are_verified_before_staging(self) -> None:
        self.assertIn("gh release download v0.9.1-honey.1", self.document)
        self.assertIn(
            "python3 scripts/release/verify_honey_release.py candidate", self.document
        )
        self.assertIn("candidate/honey-release-manifest.json", self.document)
        self.assertIn("python3 -m twine check --strict dist/*", self.document)
        self.assertIn("skip-existing: false", self.document)

    def test_oidc_is_isolated_to_data_only_publish_job(self) -> None:
        verify, publish = self.document.split("  publish-to-pypi:\n", maxsplit=1)
        self.assertNotIn("id-token: write", verify)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("actions/checkout@", publish)
        self.assertNotIn("run:", publish)
        self.assertIn(
            "pypa/gh-action-pypi-publish@ba38be9e461d3875417946c167d0b5f3d385a247",
            publish,
        )
        self.assertIn("verify-metadata: true", publish)
        self.assertIn("attestations: true", publish)
        self.assertIn("print-hash: true", publish)

    def test_python_alpha_scope_is_machine_readable(self) -> None:
        publication = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))["publication"]
        self.assertEqual(publication["pypi_project"], "hol-cigar")
        self.assertEqual(publication["pypi_release_state"], "alpha")
        self.assertEqual(publication["pypi_scope"], "python-sdk-only")
        self.assertFalse(publication["pypi_requires_full_honey_qualification"])
        self.assertEqual(
            publication["pypi_required_gate_ids"],
            [
                "authority-drift",
                "clean-committed-source",
                "focused-tests",
                "archive-contracts",
                "sdk-clean-installs",
                "docs-commands-links",
                "license-notice",
                "artifact-checksums",
            ],
        )


if __name__ == "__main__":
    unittest.main()
