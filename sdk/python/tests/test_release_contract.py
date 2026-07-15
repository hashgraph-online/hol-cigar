from __future__ import annotations

import json
import unittest
from importlib import metadata, resources

from cigar_sdk import CONTEXT_ABI
from cigar_sdk.generated import context_abi_pb2


class ReleaseContractTests(unittest.TestCase):
    def test_release_metadata_and_descriptor_bind_context_abi(self) -> None:
        release = json.loads(resources.files("cigar_sdk").joinpath("release.json").read_text(encoding="utf-8"))
        self.assertEqual(release["schema_version"], "cigar.sdk-release.v1")
        self.assertEqual(release["name"], "cigar-sdk")
        distribution_version = release["version"].replace("-dev.", ".dev")
        self.assertEqual(distribution_version, metadata.version("cigar-sdk"))
        self.assertEqual(release["context_abi"], CONTEXT_ABI)
        self.assertEqual(context_abi_pb2.DESCRIPTOR.package, CONTEXT_ABI)
        package_metadata = metadata.metadata("cigar-sdk")
        self.assertEqual(package_metadata["License-Expression"], "Apache-2.0")
        self.assertEqual(package_metadata.get_all("License-File"), ["LICENSE", "NOTICE"])


if __name__ == "__main__":
    unittest.main()
