#!/usr/bin/env python3
"""Verify public default versions and downloaded bytes against the signed release."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit
from urllib.request import urlopen

import context_distribution as distribution
import context_distribution_release as release
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    reject_evidence_directory,
)

require = distribution.require


def fetch(url: str, hosts: set[str], limit: int) -> bytes:
    parsed = urlsplit(url)
    require(
        parsed.scheme == "https"
        and parsed.hostname in hosts
        and not parsed.username
        and not parsed.password,
        "registry URL has an unexpected origin",
    )
    with urlopen(url, timeout=60) as response:
        destination = urlsplit(response.url)
        require(
            destination.scheme == "https" and destination.hostname in hosts,
            "registry redirect changed origin",
        )
        content = response.read(limit + 1)
    require(len(content) <= limit, "registry response exceeds byte limit")
    return content


def metadata(url: str, host: str) -> dict:
    return load_json_bytes(fetch(url, {host}, 16 * 1024 * 1024), "registry metadata")


def check_archive(url: str, host: str, expected: dict) -> dict:
    content = fetch(url, {host}, distribution.MAX_FILE)
    actual = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    require(
        actual == {key: expected[key] for key in ("bytes", "sha256")},
        "registry archive differs from qualified signed bytes",
    )
    return {"file": expected["file"], "url": url, **actual}


def readback(document: dict, registry: str) -> dict:
    records = {row["file"]: row for row in document["payloads"]}
    checked = {}
    if registry in {"npm", "both"}:
        data = metadata(
            "https://registry.npmjs.org/@hol-org%2Fcigar", "registry.npmjs.org"
        )
        require(
            data["name"] == "@hol-org/cigar"
            and data["dist-tags"]["latest"] == "0.11.0",
            "npm default install does not select 0.11.0",
        )
        version = data["versions"]["0.11.0"]
        require(
            version["name"] == "@hol-org/cigar" and version["version"] == "0.11.0",
            "npm version identity differs",
        )
        checked["npm"] = {
            "default": "0.11.0",
            "archives": [
                check_archive(
                    version["dist"]["tarball"],
                    "registry.npmjs.org",
                    records["hol-org-cigar-0.11.0.tgz"],
                )
            ],
        }
    if registry in {"pypi", "both"}:
        data = metadata("https://pypi.org/pypi/hol-cigar/0.11.0/json", "pypi.org")
        current = metadata("https://pypi.org/pypi/hol-cigar/json", "pypi.org")
        require(
            data["info"]["name"] == "hol-cigar"
            and data["info"]["version"] == current["info"]["version"] == "0.11.0",
            "PyPI default version differs",
        )
        expected = {name for name in records if name.startswith("hol_cigar-")}
        require(
            {row["filename"] for row in data["urls"]} == expected
            and len(data["urls"]) == len(expected) == 8,
            "PyPI does not contain the complete seven-wheel and source distribution set",
        )
        archives = []
        for row in data["urls"]:
            record = records[row["filename"]]
            require(
                row["yanked"] is False
                and row["digests"]["sha256"] == record["sha256"]
                and row["size"] == record["bytes"],
                "PyPI metadata differs from the signed archive",
            )
            archives.append(check_archive(row["url"], "files.pythonhosted.org", record))
        checked["pypi"] = {"default": "0.11.0", "archives": archives}
    return {
        "schema": "cigar.context-registry-readback.v1",
        "status": "passed",
        "release": "0.11.0",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": document["source_commit"],
        "registries": checked,
    }


def main() -> None:
    require(not sys.flags.optimize, "registry readback requires assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--registry", choices=("npm", "pypi", "both"), default="both")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "public registry readback")
    require(not args.output.exists(), "readback output already exists")
    document = release.verify(args.directory, args.commit, True, args.manifest_sha256)
    result = readback(document, args.registry)
    with args.output.open("xb") as stream:
        stream.write(canonical_json_bytes(result))
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (
        ReleaseError,
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"registry readback failed: {error}") from error
