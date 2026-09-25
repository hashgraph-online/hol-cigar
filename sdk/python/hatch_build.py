"""Tag wheels containing the explicitly staged native worker; never download/build at install."""

import hashlib
import json
import os
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return
        native = Path(self.root) / "src/cigar_sdk/_native"
        if not native.exists():
            if os.environ.get("CIGAR_ALLOW_PORTABLE_WHEEL") != "1":
                raise ValueError(
                    "native worker is not staged; set CIGAR_ALLOW_PORTABLE_WHEEL=1 "
                    "only for an intentional SDK-only source/development wheel, "
                    "then supply a matching trusted worker_path"
                )
            return
        manifests = list(native.glob("*/manifest.json"))
        if len(manifests) != 1:
            raise ValueError("stage exactly one native target per platform wheel")
        manifest = json.loads(manifests[0].read_bytes())
        package = Path(self.root) / "src/cigar_sdk"
        inventory = json.loads((package / "native-platforms.v1.json").read_bytes())
        if inventory.get("schema") != "cigar.native-platforms.v1":
            raise ValueError("invalid native platform inventory")
        platforms = {entry["id"]: entry for entry in inventory["platforms"]}
        target = manifests[0].parent.name
        if target not in platforms:
            raise ValueError("native wheel target is outside the release platform inventory")
        metadata = platforms[target]
        release = json.loads((package / "release.json").read_bytes())
        if (
            manifest.get("target") != metadata["target"]
            or manifest.get("core_version") != release["local_context_core_version"]
            or manifest.get("protocol") != release["local_context_protocol"]
            or manifest.get("sdk_release") != release["version"]
        ):
            raise ValueError("native worker platform/version/protocol mismatch")
        worker = manifests[0].parent / metadata["executable"]
        if hashlib.sha256(worker.read_bytes()).hexdigest() != manifest["sha256"]:
            raise ValueError("native worker checksum mismatch")
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{metadata['wheel_tag']}"
