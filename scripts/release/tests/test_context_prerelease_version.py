"""Closed RC version mapping without weakening stable channel identities."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_context_version import local_version  # noqa: E402
from context_distribution import npm_publication_tag  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class ContextPrereleaseVersion(unittest.TestCase):
    def test_supported_mappings(self):
        self.assertEqual(local_version("0.14.2"), ("0.14.2", "stable"))
        self.assertEqual(local_version("0.14.2-alpha.1"), ("0.14.2a1", "alpha"))
        self.assertEqual(local_version("0.14.2-rc.2"), ("0.14.2rc2", "rc"))

    def test_unregistered_suffixes_and_zero_candidates_are_rejected(self):
        for version in ("0.14.2.rc2", "0.14.2-rc.0", "0.14.2-rc.02", "0.14.2-beta.2", "0.14.2-rc.2+local"):
            with self.subTest(version=version), self.assertRaises(AssertionError):
                local_version(version)

    def test_npm_tag_binds_version_and_channel_without_latest_fallback(self):
        self.assertEqual(npm_publication_tag("0.14.2", "stable"), "latest")
        self.assertEqual(npm_publication_tag("0.14.2-alpha.1", "alpha"), "alpha")
        self.assertEqual(npm_publication_tag("0.14.2-rc.2", "rc"), "rc")
        for version, channel in (("0.14.2-rc.2", "stable"), ("0.14.2", "rc"),
                                 ("0.14.2-rc.2", "latest"), ("0.14.2-alpha.1", "rc")):
            with self.subTest(version=version, channel=channel), self.assertRaises(ReleaseError):
                npm_publication_tag(version, channel)
