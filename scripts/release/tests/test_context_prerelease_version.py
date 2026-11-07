"""Closed RC version mapping without weakening stable channel identities."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_context_version import local_version  # noqa: E402


class ContextPrereleaseVersion(unittest.TestCase):
    def test_supported_mappings(self):
        self.assertEqual(local_version("0.14.2"), ("0.14.2", "stable"))
        self.assertEqual(local_version("0.14.2-alpha.1"), ("0.14.2a1", "alpha"))
        self.assertEqual(local_version("0.14.2-rc.2"), ("0.14.2rc2", "rc"))

    def test_unregistered_suffixes_and_zero_candidates_are_rejected(self):
        for version in ("0.14.2.rc2", "0.14.2-rc.0", "0.14.2-rc.02", "0.14.2-beta.2", "0.14.2-rc.2+local"):
            with self.subTest(version=version), self.assertRaises(AssertionError):
                local_version(version)
