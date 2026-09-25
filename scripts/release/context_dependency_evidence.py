"""Read runtime dependency identities from an actual installed SDK environment."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
from pathlib import Path
import re


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def python_receipt() -> dict:
    from packaging.requirements import Requirement

    root = metadata.distribution("hol-cigar")
    requirements = [Requirement(value) for value in root.requires or []]
    active = [
        item for item in requirements if item.marker is None or item.marker.evaluate()
    ]
    components = []
    for requirement in active:
        installed = metadata.distribution(requirement.name)
        if installed.version not in requirement.specifier:
            raise ValueError("installed dependency violates wheel metadata")
        document = installed.metadata
        components.append(
            {
                "name": document["Name"],
                "version": installed.version,
                "license": document.get("License-Expression")
                or document.get("License"),
                "metadata_sha256": sha256(installed.read_text("METADATA") or ""),
                "record_sha256": sha256(installed.read_text("RECORD") or ""),
            }
        )
    return {
        "schema": "cigar.installed-runtime-dependencies.v1",
        "ecosystem": "pypi",
        "name": root.metadata["Name"],
        "version": root.version,
        "requirements": root.requires or [],
        "components": components,
    }


def npm_receipt(directory: Path) -> dict:
    root = json.loads(
        (directory / "node_modules/@hol-org/cigar/package.json").read_bytes()
    )
    lock = json.loads((directory / "package-lock.json").read_bytes())
    components = []
    for name, required in root.get("dependencies", {}).items():
        # The local SDK intentionally pins its Node runtime dependency exactly.
        if re.fullmatch(r"\d+\.\d+\.\d+", required) is None:
            raise ValueError(
                "npm dependency evidence requires an exact qualified version"
            )
        path = directory / "node_modules" / name / "package.json"
        text = path.read_text()
        package = json.loads(text)
        resolution = lock["packages"]["node_modules/" + name]
        if (
            package["name"] != name
            or package["version"] != required
            or resolution["version"] != required
        ):
            raise ValueError(
                "installed npm dependency differs from archive/lock metadata"
            )
        components.append(
            {
                "name": name,
                "version": package["version"],
                "license": package.get("license"),
                "metadata_sha256": sha256(text),
                "integrity": resolution["integrity"],
            }
        )
    return {
        "schema": "cigar.installed-runtime-dependencies.v1",
        "ecosystem": "npm",
        "name": root["name"],
        "version": root["version"],
        "requirements": root.get("dependencies", {}),
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("python", "npm"))
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    receipt = python_receipt() if args.kind == "python" else npm_receipt(args.directory)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
