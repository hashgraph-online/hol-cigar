"""Print the verified shared SDK semantic bundle identity."""

from __future__ import annotations

import json
import sys
from importlib import resources  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from pathlib import Path
from typing import Any

from cigar_sdk.digest import bundle_id, verify_bundle


def main() -> None:
    source = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else resources.files("cigar_sdk.fixtures").joinpath("semantic-bundle-v1.json")
    )
    fixture: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "cigar.sdk-semantic-bundle-fixture.v1":
        raise ValueError("unsupported semantic bundle fixture")
    bundle = fixture["bundle"]
    if not isinstance(bundle, dict):
        raise ValueError("fixture bundle must be an object")
    verify_bundle(bundle)
    computed = bundle_id(bundle)
    if computed != fixture.get("expected_bundle_id"):
        raise ValueError("shared semantic bundle identity differs")
    print(computed)


if __name__ == "__main__":
    main()
