#!/usr/bin/env python3
"""Run the shared handoff driver against the Honey two-agent fixture."""

from __future__ import annotations

import runpy
import hashlib
from pathlib import Path


SHARED_DRIVER_SHA256 = (
    "5a2d4cacc4e2fcad51a944ebd4a2e128a801b7e22c81f5b212172bf25c5834a0"
)


if __name__ == "__main__":
    shared_driver = Path(__file__).resolve().parents[1] / "agent-handoff" / "driver.py"
    if hashlib.sha256(shared_driver.read_bytes()).hexdigest() != SHARED_DRIVER_SHA256:
        raise SystemExit("honey two-agent driver dependency does not match")
    runpy.run_path(
        str(shared_driver),
        run_name="__main__",
    )
