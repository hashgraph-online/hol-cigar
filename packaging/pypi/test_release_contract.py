from __future__ import annotations

import json
import unittest
from importlib import metadata, resources

from cigar_sdk import CONTEXT_ABI
from cigar_sdk.generated import context_abi_pb2


class ReleaseContractTests(unittest.TestCase):
    def test_pypi_identity_and_protocol_attribution(self) -> None:
        release = json.loads(
            resources.files("cigar_sdk")
            .joinpath("release.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(release["schema_version"], "cigar.sdk-release.v1")
        self.assertEqual(release["name"], "hol-cigar")
        self.assertEqual(release["version"], "0.9.1")
        self.assertEqual(release["release_state"], "developer-preview")
        self.assertEqual(release["protocol_home"], "https://hol.org")
        self.assertEqual(release["context_abi"], CONTEXT_ABI)
        self.assertEqual(context_abi_pb2.DESCRIPTOR.package, CONTEXT_ABI)

        package = metadata.metadata("hol-cigar")
        self.assertEqual(metadata.version("hol-cigar"), "0.9.1")
        self.assertEqual(package["License-Expression"], "Apache-2.0")
        self.assertEqual(package.get_all("License-File"), ["LICENSE", "NOTICE"])
        self.assertIn(
            "Development Status :: 3 - Alpha",
            package.get_all("Classifier", []),
        )


if __name__ == "__main__":
    unittest.main()
