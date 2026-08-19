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
        self.assertEqual(release["name"], "hol-cigar")
        distribution_version = release["version"].replace("-honey.", ".dev")
        self.assertEqual(distribution_version, metadata.version("hol-cigar"))
        self.assertEqual(release["context_abi"], CONTEXT_ABI)
        self.assertEqual(context_abi_pb2.DESCRIPTOR.package, CONTEXT_ABI)
        package_metadata = metadata.metadata("hol-cigar")
        self.assertEqual(package_metadata["License-Expression"], "Apache-2.0")
        self.assertEqual(package_metadata.get_all("License-File"), ["LICENSE", "NOTICE"])
        self.assertEqual(
            package_metadata.get_all("Project-URL"),
            [
                "Homepage, https://hol.org",
                "Repository, https://github.com/hashgraph-online/hol-cigar",
                "Issues, https://github.com/hashgraph-online/hol-cigar/issues",
            ],
        )


if __name__ == "__main__":
    unittest.main()
