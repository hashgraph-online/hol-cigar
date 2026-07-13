#!/usr/bin/env python3
"""Generate the byte-exact CIGAR Claude plugin package manifest."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "package-manifest.json"


def main() -> None:
    files: list[dict[str, object]] = []
    for path in sorted(ROOT.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if path == MANIFEST:
            continue
        if path.is_symlink():
            raise SystemExit(f"symlink is not packageable: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        data = path.read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    document = {
        "schema_version": "cigar.claude-code-package.v1",
        "files": files,
    }
    temporary = MANIFEST.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, MANIFEST)


if __name__ == "__main__":
    main()
