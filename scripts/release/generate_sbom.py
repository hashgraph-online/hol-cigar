#!/usr/bin/env python3
"""Generate deterministic SPDX 2.3 and CycloneDX 1.6 SBOMs from locked inputs and final artifacts."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import re
import tomllib
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    repo_root,
    require_source_date_epoch,
    sha256_bytes,
    sha256_file,
    write_json,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--require-reviewed-licenses", action="store_true")
    return parser.parse_args()


def _purl(ecosystem: str, name: str, version: str) -> str:
    return f"pkg:{ecosystem}/{urllib.parse.quote(name, safe='/')}@{urllib.parse.quote(version, safe='.+-_')}"


def _component(ecosystem: str, name: str, version: str, checksum: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "purl": _purl(ecosystem, name, version),
    }
    if checksum is not None and re.fullmatch(r"[0-9a-f]{64}", checksum):
        result["sha256"] = checksum
    return result


def _cargo_components(root: Path) -> list[dict[str, Any]]:
    lock = root / "Cargo.lock"
    document = tomllib.loads(lock.read_text(encoding="utf-8"))
    components: list[dict[str, Any]] = []
    for package in document.get("package", []):
        source = package.get("source", "")
        ecosystem = "cargo" if source.startswith("registry+") or source.startswith("git+") else "generic"
        components.append(_component(ecosystem, package["name"], package["version"], package.get("checksum")))
    return components


def _python_components(root: Path) -> list[dict[str, Any]]:
    lock = root / "sdk/python/uv.lock"
    document = tomllib.loads(lock.read_text(encoding="utf-8"))
    components: list[dict[str, Any]] = []
    for package in document.get("package", []):
        checksum = None
        source_distribution = package.get("sdist")
        if isinstance(source_distribution, dict):
            candidate = source_distribution.get("hash")
            if isinstance(candidate, str) and candidate.startswith("sha256:"):
                checksum = candidate.removeprefix("sha256:")
        components.append(_component("pypi", package["name"], package["version"], checksum))
    return components


_PNPM_PACKAGE = re.compile(r"^  (?! )['\"]?(.+)@([^@:'\"]+)['\"]?:$")
_PNPM_INTEGRITY = re.compile(r"^    resolution: \{integrity: sha512-([^}]+)\}$")


def _npm_components(root: Path) -> list[dict[str, Any]]:
    lines = (root / "pnpm-lock.yaml").read_text(encoding="utf-8").splitlines()
    components: list[dict[str, Any]] = []
    in_packages = False
    current: dict[str, Any] | None = None
    for line in lines:
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages:
            continue
        package_match = _PNPM_PACKAGE.match(line)
        if package_match is not None:
            if current is not None:
                components.append(current)
            current = _component("npm", package_match.group(1), package_match.group(2))
            continue
        integrity_match = _PNPM_INTEGRITY.match(line)
        if integrity_match is not None and current is not None:
            try:
                digest = base64.b64decode(integrity_match.group(1), validate=True)
            except ValueError as error:
                raise ReleaseError(f"invalid pnpm SHA-512 integrity for {current['purl']}") from error
            if len(digest) != 64:
                raise ReleaseError(f"pnpm integrity is not a SHA-512 digest for {current['purl']}")
            current["sha512"] = digest.hex()
    if current is not None:
        components.append(current)
    return components


def _go_components(root: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (root / "sdk/go/go.sum").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1].endswith("/go.mod"):
            continue
        key = (fields[0], fields[1])
        if key in seen:
            continue
        seen.add(key)
        component = _component("golang", fields[0], fields[1])
        if fields[2].startswith("h1:"):
            try:
                digest = base64.b64decode(fields[2][3:], validate=True)
            except ValueError as error:
                raise ReleaseError(f"invalid Go h1 checksum for {fields[0]}@{fields[1]}") from error
            if len(digest) != 32:
                raise ReleaseError(f"Go h1 checksum is not a SHA-256 digest for {fields[0]}@{fields[1]}")
            component["sha256"] = digest.hex()
        components.append(component)
    return components


def _spdx_id(component: dict[str, Any]) -> str:
    import hashlib

    suffix = hashlib.sha256(component["purl"].encode("utf-8")).hexdigest()[:20]
    return f"SPDXRef-Package-{suffix}"


def _workspace_package_names(root: Path) -> set[str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    result: set[str] = set()
    for member in workspace.get("workspace", {}).get("members", []):
        manifest = root / member / "Cargo.toml"
        if manifest.is_file():
            result.add(tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["name"])
    return result


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    artifacts: list[dict[str, Any]] = []
    artifact_inputs: dict[str, Path] = {}
    for supplied in arguments.artifact:
        if supplied.is_symlink():
            raise ReleaseError(f"artifact must not be a symlink: {supplied}")
        path = supplied.absolute()
        if not path.is_file():
            raise ReleaseError(f"artifact does not exist: {path}")
        size = path.stat().st_size
        if size <= 0:
            raise ReleaseError(f"artifact is empty: {path}")
        if path.name in artifact_inputs:
            raise ReleaseError(f"SBOM artifacts have duplicate basenames: {path.name}")
        artifact_inputs[path.name] = path
        artifacts.append({"name": path.name, "sha256": sha256_file(path), "bytes": size})
    artifacts.sort(key=lambda item: item["name"])
    if len({item["name"] for item in artifacts}) != len(artifacts):
        raise ReleaseError("SBOM artifacts have duplicate basenames")

    components = _cargo_components(root) + _npm_components(root) + _python_components(root) + _go_components(root)
    component_keys = [(component["ecosystem"], component["name"], component["version"]) for component in components]
    if len(set(component_keys)) != len(component_keys):
        raise ReleaseError("locked SBOM inputs contain ambiguous duplicate component identities")
    unique = {key: component for key, component in zip(component_keys, components, strict=True)}
    components = sorted(unique.values(), key=lambda item: (item["ecosystem"], item["name"], item["version"]))
    if not components:
        raise ReleaseError("locked dependency inventory is empty")
    inventory_path = root / "packaging/licenses/third-party-inventory.v1.json"
    inventory = load_json(inventory_path) if inventory_path.is_file() else {"components": []}
    policy_path = root / "packaging/licenses/third-party-policy.v1.json"
    if inventory.get("policy_sha256") != sha256_file(policy_path):
        raise ReleaseError("third-party license inventory is missing or stale")
    if arguments.require_reviewed_licenses and inventory.get("review_required_count") != 0:
        raise ReleaseError("SBOM generation requires a fully reviewed third-party license inventory")
    inventory_components = inventory.get("components")
    if (
        not isinstance(inventory_components, list)
        or inventory.get("component_count") != len(inventory_components)
        or any(not isinstance(entry, dict) or not isinstance(entry.get("purl"), str) for entry in inventory_components)
    ):
        raise ReleaseError("third-party license inventory component set is invalid")
    inventory_purls = [entry["purl"] for entry in inventory_components]
    if len(set(inventory_purls)) != len(inventory_purls):
        raise ReleaseError("third-party license inventory contains duplicate purls")
    license_by_purl = {
        entry["purl"]: (entry.get("license_expression", "NOASSERTION"), entry.get("policy_status", "review-required"))
        for entry in inventory_components
    }
    workspace_package_names = _workspace_package_names(root)
    external_purls = {
        component["purl"]
        for component in components
        if not (
            (component["ecosystem"] == "generic" and component["name"] in workspace_package_names)
            or (component["ecosystem"] == "pypi" and component["name"] == "cigar-sdk")
        )
    }
    if set(inventory_purls) != external_purls:
        missing = sorted(external_purls - set(inventory_purls))
        extra = sorted(set(inventory_purls) - external_purls)
        raise ReleaseError(f"third-party license inventory differs from locked components; missing={missing[:10]}, extra={extra[:10]}")

    def component_license(component: dict[str, Any]) -> tuple[str, str]:
        result = license_by_purl.get(component["purl"], ("NOASSERTION", "review-required"))
        if (component["ecosystem"] == "generic" and component["name"] in workspace_package_names) or (
            component["ecosystem"] == "pypi" and component["name"] == "cigar-sdk"
        ):
            result = ("Apache-2.0", "accepted-by-policy")
        return result

    unresolved = [
        component["purl"]
        for component in components
        if component_license(component)[0] == "NOASSERTION" or component_license(component)[1] != "accepted-by-policy"
    ]
    if arguments.require_reviewed_licenses and unresolved:
        raise ReleaseError(f"SBOM contains {len(unresolved)} unreviewed locked components")

    artifact_binding = canonical_json_bytes(artifacts).decode("utf-8").rstrip("\n")
    document_identity = {
        "artifacts": artifacts,
        "components": [
            {
                **component,
                "license_expression": component_license(component)[0],
                "policy_status": component_license(component)[1],
            }
            for component in components
        ],
    }
    document_digest = sha256_bytes(canonical_json_bytes(document_identity))
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    product_version = matrix.get("product_version")
    if not isinstance(product_version, str) or not product_version:
        raise ReleaseError("artifact matrix product version is invalid")

    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.UTC).isoformat().replace("+00:00", "Z")
    output = arguments.out.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ReleaseError("SBOM output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)

    spdx_packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for component in components:
        license_expression, policy_status = component_license(component)
        package: dict[str, Any] = {
            "SPDXID": _spdx_id(component),
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": license_expression if policy_status == "accepted-by-policy" else "NOASSERTION",
            "licenseDeclared": license_expression,
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component["purl"]}],
        }
        checksums = []
        if "sha256" in component:
            checksums.append({"algorithm": "SHA256", "checksumValue": component["sha256"]})
        if "sha512" in component:
            checksums.append({"algorithm": "SHA512", "checksumValue": component["sha512"]})
        if checksums:
            package["checksums"] = checksums
        spdx_packages.append(package)
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package["SPDXID"]})
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"cigar-release-{document_digest[:16]}",
        "documentNamespace": f"https://cigar.invalid/sbom/{document_digest}",
        "creationInfo": {"created": timestamp, "creators": ["Tool: cigar-release-sbom-v1"]},
        "documentDescribes": [_spdx_id(component) for component in components],
        "packages": spdx_packages,
        "relationships": relationships,
        "annotations": [{"annotationDate": timestamp, "annotationType": "OTHER", "annotator": "Tool: cigar-release-sbom-v1", "comment": f"CIGAR artifact binding: {artifact_binding}"}],
    }

    cdx_components: list[dict[str, Any]] = []
    for component in components:
        license_expression, policy_status = component_license(component)
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": component["purl"],
            "name": component["name"],
            "version": component["version"],
            "purl": component["purl"],
            "licenses": [{"expression": license_expression}],
            "properties": [{"name": "cigar:license-policy-status", "value": policy_status}],
        }
        hashes = []
        if "sha256" in component:
            hashes.append({"alg": "SHA-256", "content": component["sha256"]})
        if "sha512" in component:
            hashes.append({"alg": "SHA-512", "content": component["sha512"]})
        if hashes:
            entry["hashes"] = hashes
        cdx_components.append(entry)
    serial = uuid.UUID(document_digest[:32], version=5)
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "cigar-release-sbom", "version": "1"}]},
            "component": {"type": "application", "name": "cigar", "version": product_version, "properties": [{"name": "cigar:artifacts", "value": artifact_binding}]},
        },
        "components": cdx_components,
    }
    for record in artifacts:
        path = artifact_inputs[record["name"]]
        if path.stat().st_size != record["bytes"] or sha256_file(path) != record["sha256"]:
            raise ReleaseError(f"artifact changed during SBOM generation: {path}")
    write_json(output / "sbom.spdx.json", spdx)
    write_json(output / "sbom.cyclonedx.json", cyclonedx)
    write_json(output / "sbom-artifacts.json", {"schema_version": "cigar.sbom-artifacts.v1", "artifacts": artifacts, "component_count": len(components)})
    print(f"generated SPDX and CycloneDX SBOMs for {len(artifacts)} artifact(s), {len(components)} locked components")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, tomllib.TOMLDecodeError, ReleaseError) as error:
        raise SystemExit(f"SBOM generation failed: {error}") from error
