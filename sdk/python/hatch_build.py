"""Tag wheels containing the explicitly staged native worker; never download/build at install."""

import hashlib
import json
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return
        native = Path(self.root) / "src/cigar_sdk/_native"
        if not native.exists():
            # Portable SDK-only wheel/sdist: local graphs require an explicit worker_path.
            return
        manifests = list(native.glob("*/manifest.json"))
        if len(manifests) != 1:
            raise ValueError("stage exactly one native target per platform wheel")
        manifest = json.loads(manifests[0].read_bytes())
        platform_tags = {"darwin-arm64": "macosx_11_0_arm64"}
        target = manifests[0].parent.name
        if target not in platform_tags:
            raise ValueError("native wheel target has not been qualified by this RC profile")
        worker = manifests[0].parent / "cigar-context-worker"
        if hashlib.sha256(worker.read_bytes()).hexdigest() != manifest["sha256"]:
            raise ValueError("native worker checksum mismatch")
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{platform_tags[target]}"
